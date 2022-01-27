#!/usr/bin/python3

import argparse
import hashlib
import multiprocessing
import os.path
import queue
import re
import shutil
import signal
import ssl
import sys
import time
import traceback
from importlib import reload
from random import shuffle
from urllib.parse import urlparse
from collections import defaultdict

import warnings

warnings.filterwarnings("ignore")

import M2Crypto
from PIL import Image, ImageDraw, ImageFont
from pyvirtualdisplay import Display
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
from webdriver_manager.chrome import ChromeDriverManager

try:
    from urllib.parse import quote
except Exception:
    from urllib.parse import quote

try:
    import requesocks as requests
except Exception:
    import requests

reload(sys)


def timeoutFn(func, args=(), kwargs={}, timeout_duration=1, default=None):
    class TimeoutError(Exception):
        pass

    def handler(signum, frame):
        raise TimeoutError()

    # set the timeout handler
    signal.signal(signal.SIGALRM, handler)
    signal.alarm(timeout_duration)
    try:
        result = func(*args, **kwargs)
    except TimeoutError as exc:
        result = default
    finally:
        signal.alarm(0)

    return result


def addUrlsForService(host, urlList, servicesList, scheme):
    if servicesList is None or servicesList == []:
        return
    for service in servicesList:
        state = service.findPreviousSibling("state")
        if state is not None and state != [] and state["state"] == "open":
            urlList.append(scheme + host + ":" + str(service.parent["portid"]))


def detectFileType(inFile):
    # Check to see if file is of type gnmap
    firstLine = inFile.readline()
    secondLine = inFile.readline()
    thirdLine = inFile.readline()

    # Be polite and reset the file pointer
    inFile.seek(0)

    if (firstLine.find("nmap") != -1 or firstLine.find("Masscan") != -1) and thirdLine.find("Host:") != -1:
        # Looks like a gnmap file - this wont be true for other nmap output types
        # Check to see if -sV flag was used, if not, warn
        if firstLine.find("-sV") != -1 or firstLine.find("-A") != -1:
            return "gnmap"
        else:
            print(
                "Nmap version detection not used! Discovery module may miss some hosts!"
            )
            return "gnmap"
    elif (firstLine.find("xml version") !=
          -1) and (secondLine.find("DOCTYPE nmaprun") != -1
                   or secondLine.find("masscan") != -1):
        return "xml"
    else:
        return None


def parsexml(inFile):
    import xml.etree.ElementTree as ET

    tree = ET.parse(inFile)
    root = tree.getroot()

    targets = defaultdict(list)

    for host in root.findall("host"):
        ip = host.find('address').get('addr')

        for port in host.find('ports').findall("port"):
            if port.find("state").get("state") == "open":
                targets[ip].append(port.get("portid"))

    return targets


def parseGnmap(inFile, autodetect):
    hostRe = re.compile('Host:\s*[^\s]+')
    servicesRe = re.compile('Ports:\s*.*')

    targets = defaultdict(list)

    for hostLine in inFile:
        if hostLine.strip() == "":
            break
        # Pull out the IP address (or hostnames) and HTTP service ports

        ipHostRes = hostRe.search(hostLine)

        if ipHostRes is None:
            continue

        ipHost = ipHostRes.group()
        ip = ipHost.split(':')[1].strip()

        try:
            services = servicesRe.search(hostLine).group().split()
        except:
            continue

        for item in services:
            # Make sure we have an open port with an http type service on it
            if re.findall("\d+/open", item):
                port = None
                https = False
                """
                                nmap has a bunch of ways to list HTTP like services, for example:
                                8089/open/tcp//ssl|http
                                8000/closed/tcp//http-alt///
                                8008/closed/tcp//http///
                                8080/closed/tcp//http-proxy//
                                443/open/tcp//ssl|https?///
                                8089/open/tcp//ssl|http
                                Since we want to detect them all, let's just match on the word http
                                and make special cases for things containing https and ssl when we
                                construct the URLs.
                                """
                port = item.split("/")[0]
                targets[ip].append(port)

    return targets


def setupBrowserProfile(headless, proxy, browserType):
    browser = None
    if (proxy is not None):
        service_args = ['--ignore-ssl-errors=true', '--ssl-protocol=any', '--proxy=' + proxy, '--proxy-type=socks5']
    else:
        service_args = ['--ignore-ssl-errors=true', '--ssl-protocol=any']

    while (browser is None):
        try:
            if (browserType == 'Chrome' or browserType == 'Chromium'):
                service = Service(ChromeDriverManager(log_level=0).install())
                coptions = Options()
                if headless:
                    coptions.add_argument("--headless")
                coptions.add_argument("--no-sandbox")
                coptions.add_argument("--window-size=1024x768")
                coptions.add_argument("--ignore-certificate-errors")
                coptions.add_argument("--ssl-version-min=tls1")

                browser = webdriver.Chrome(service=service, options=coptions)
            else:
                capabilities = DesiredCapabilities.FIREFOX
                capabilities['acceptSslCerts'] = True
                fp = webdriver.FirefoxProfile()
                fp.set_preference("webdriver.accept.untrusted.certs", True)
                fp.set_preference("security.enable_java", False)
                fp.set_preference("webdriver.load.strategy", "fast");
                if (proxy is not None):
                    proxyItems = proxy.split(":")
                    fp.set_preference("network.proxy.socks", proxyItems[0])
                    fp.set_preference("network.proxy.socks_port", int(proxyItems[1]))
                    fp.set_preference("network.proxy.type", 1)

                fireFoxOptions = webdriver.FirefoxOptions()
                if headless:
                    fireFoxOptions.headless = True

                browser = webdriver.Firefox(firefox_profile=fp,
                                            capabilities=capabilities,
                                            options=fireFoxOptions)
                browser.set_window_size(1024, 768)

        except Exception as e:
            print(e)
            time.sleep(1)
            continue
    return browser


def writeImage(text, filename, fontsize=40, width=1024, height=200):
    image = Image.new("RGBA", (width, height), (255, 255, 255))
    draw = ImageDraw.Draw(image)
    if os.path.exists(
            "/usr/share/httpscreenshot/LiberationSerif-BoldItalic.ttf"):
        font_path = "/usr/share/httpscreenshot/LiberationSerif-BoldItalic.ttf"
    else:
        font_path = (os.path.dirname(os.path.realpath(__file__)) +
                     "/LiberationSerif-BoldItalic.ttf")
    font = ImageFont.truetype(font_path, fontsize)
    draw.text((10, 0), text, (0, 0, 0), font=font)
    image.save(filename)


def worker(
        urlQueue,
        tout,
        debug,
        headless,
        doProfile,
        vhosts,
        subs,
        extraHosts,
        tryGUIOnFail,
        smartFetch,
        proxy,
        browserType
):
    if debug:
        print("[*] Starting worker")

    browser = None
    display = None
    try:
        if tryGUIOnFail or not headless:
            display = Display(visible=0, size=(800, 600))
            display.start()

        browser = setupBrowserProfile(headless, proxy, browserType)

    except Exception:
        print("[-] Oh no! Couldn't create the browser, Selenium blew up")
        exc_type, exc_value, exc_traceback = sys.exc_info()
        lines = traceback.format_exception(exc_type, exc_value, exc_traceback)
        print("".join("!! " + line for line in lines))
        browser.quit()
        display.stop()
        return

    while True:
        # Try to get a URL from the Queue
        if urlQueue.qsize() > 0:
            try:
                curUrl = urlQueue.get(timeout=tout)
            except queue.Empty:
                continue
            print("[+] " + str(urlQueue.qsize()) + " URLs remaining")
            screenshotName = quote(curUrl, safe="")
            if debug:
                print("[+] Got URL: " + curUrl)
                print("[+] screenshotName: " + screenshotName)
            if os.path.exists(screenshotName + ".png"):
                if debug:
                    print("[-] Screenshot already exists, skipping")
                continue
        else:
            if debug:
                print("[-] URL queue is empty, quitting.")
            browser.quit()
            return

        try:
            if doProfile:
                [resp, curUrl] = autodetectRequest(
                    curUrl,
                    timeout=tout,
                    vhosts=vhosts,
                    urlQueue=urlQueue,
                    subs=subs,
                    extraHosts=extraHosts,
                    proxy=proxy,
                )
            else:
                resp = doGet(
                    curUrl,
                    verify=False,
                    timeout=tout,
                    vhosts=vhosts,
                    urlQueue=urlQueue,
                    subs=subs,
                    extraHosts=extraHosts,
                    proxy=proxy,
                )
            if resp is not None and resp.status_code == 401:
                print(curUrl + " Requires HTTP Basic Auth")
                f = open(screenshotName + ".html", "w")
                f.write(resp.headers.get("www-authenticate", "NONE"))
                f.write("<title>Basic Auth</title>")
                f.close()
                writeImage(
                    resp.headers.get("www-authenticate",
                                     "NO WWW-AUTHENTICATE HEADER"),
                    screenshotName + ".png",
                )
                continue

            elif resp is not None:
                if resp.text is not None:
                    resp_hash = hashlib.md5(
                        resp.text.encode('utf-8')).hexdigest()
                else:
                    resp_hash = None

                if smartFetch and resp_hash is not None and resp_hash in hash_basket:
                    # We have this exact same page already, copy it instead of grabbing it again
                    print(
                        "[+] Pre-fetch matches previously imaged service, no need to do it again!"
                    )
                    shutil.copy2(hash_basket[resp_hash] + ".html",
                                 screenshotName + ".html")
                    shutil.copy2(hash_basket[resp_hash] + ".png",
                                 screenshotName + ".png")
                else:
                    if smartFetch:
                        hash_basket[resp_hash] = screenshotName

                browser.set_page_load_timeout((tout))
                old_url = browser.current_url
                browser.get(curUrl.strip())
                if browser.current_url == old_url:
                    print(
                        "[-] Error fetching in browser but successfully fetched with Requests: "
                        + curUrl)
                    if tryGUIOnFail and headless:
                        display = Display(visible=0, size=(1024, 768))
                        display.start()
                        print("[+] Attempting to fetch with FireFox: " +
                              curUrl)
                        browser2 = setupBrowserProfile(False, proxy, "Firefox")
                        old_url = browser2.current_url
                        try:
                            browser2.get(curUrl.strip())
                            if browser2.current_url == old_url:
                                print(
                                    "[-] Error fetching in GUI browser as well..."
                                    + curUrl)
                                browser2.quit()
                                continue
                            else:
                                print("[+] Saving: " + screenshotName)
                                html_source = browser2.page_source
                                f = open(screenshotName + ".html", "w")
                                f.write(html_source)
                                f.close()
                                browser2.save_screenshot(screenshotName +
                                                         ".png")
                                browser2.quit()
                                continue
                        except Exception:
                            browser2.quit()
                            display.stop()
                            print(
                                "[-] Error fetching in GUI browser as well..."
                                + curUrl)

                    else:
                        continue

                print("[+] Saving: " + screenshotName)
                html_source = browser.page_source
                f = open(screenshotName + ".html", "w")
                f.write(html_source)
                f.close()
                browser.save_screenshot(screenshotName + ".png")

        except Exception as e:
            if debug:
                exc_type, exc_value, exc_traceback = sys.exc_info()
                lines = traceback.format_exception(exc_type, exc_value,
                                                   exc_traceback)
                print("".join("!! " + line for line in lines))
            browser.quit()
            browser = setupBrowserProfile(headless, proxy, "Firefox")
            continue
    browser.quit()
    display.stop()


def doGet(*args, **kwargs):
    url = args[0]
    doVhosts = kwargs.pop("vhosts", None)
    urlQueue = kwargs.pop("urlQueue", None)
    subs = kwargs.pop("subs", None)
    extraHosts = kwargs.pop("extraHosts", None)
    proxy = kwargs.pop("proxy", None)

    kwargs["allow_redirects"] = False
    session = requests.session()
    if proxy is not None:
        session.proxies = {
            "http": "socks5://" + proxy,
            "https": "socks5://" + proxy
        }
    resp = session.get(url, **kwargs)

    # If we have an https URL and we are configured to scrape hosts from the cert...
    if url.find("https") != -1 and doVhosts is True:
        # Pull hostnames from cert, add as additional URLs and flag as not to pull certs
        host = urlparse(url).hostname
        port = urlparse(url).port
        if port is None:
            port = 443
        names = []
        try:
            cert = ssl.get_server_certificate((host, port))
            x509 = M2Crypto.X509.load_cert_string(cert)
            subjText = x509.get_subject().as_text()
            names = re.findall("CN=([^\s]+)", subjText)
            altNames = x509.get_ext("subjectAltName").get_value()
            names.extend(re.findall("DNS:([^,]*)", altNames))
        except Exception as e:
            print(e)

        for name in names:
            if name not in extraHosts:
                extraHosts[name] = 1
                urlQueue.put(f"https://{name}:{port}")
                print(f"[+] Added host https://{name}:{port}")
        return resp
    else:
        return resp


def autodetectRequest(url,
                      timeout,
                      vhosts=False,
                      urlQueue=None,
                      subs=None,
                      extraHosts=None,
                      proxy=None):
    """Takes a URL, ignores the scheme. Detect if the host/port is actually an HTTP or HTTPS
    server"""
    resp = None
    host = urlparse(url).hostname
    port = urlparse(url).port

    try:
        # cert = ssl.get_server_certificate((host,port))

        cert = timeoutFn(
            ssl.get_server_certificate,
            kwargs={"addr": (host, port)},
            timeout_duration=3,
        )

        if cert is not None:
            if "https" not in url:
                url = url.replace("http://", "https://")
        else:
            url = url.replace("https://", "http://")

    except Exception:
        url = url.replace("https://", "http://")
    try:
        resp = doGet(
            url,
            verify=False,
            timeout=timeout,
            vhosts=vhosts,
            urlQueue=urlQueue,
            subs=subs,
            extraHosts=extraHosts,
            proxy=proxy,
        )
    except Exception as e:
        print("HTTP GET Error: " + str(e))
        print(url)

    return [resp, url]


def sslError(e):
    if ("the handshake operation timed out" in str(e)
            or "unknown protocol" in str(e)
            or "Connection reset by peer" in str(e)
            or "EOF occurred in violation of protocol" in str(e)):
        return True
    else:
        return False


def signal_handler(signal, frame):
    print("[-] Ctrl-C received! Killing Thread(s)...")
    os._exit(0)


signal.signal(signal.SIGINT, signal_handler)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument("-l", "--list", help="List of input URLs")
    parser.add_argument("-i", "--input", help="nmap gnmap/xml output file")
    parser.add_argument(
        "-p",
        "--headless",
        action="store_true",
        default=False,
        help="Run in headless mode (using phantomjs)",
    )
    parser.add_argument(
        "-b",
        "--browsertype",
        default="Firefox",
        help="Choose webdriver {Firefox, Chrome}"
    )
    parser.add_argument("-w",
                        "--workers",
                        default=1,
                        type=int,
                        help="number of threads")
    parser.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=10,
        help="time to wait for pageload before killing the browser",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        default=False,
        help="turn on verbose debugging",
    )
    parser.add_argument(
        "-a",
        "--autodetect",
        action="store_true",
        default=False,
        help=
        "Automatically detect if listening services are HTTP or HTTPS. Ignores NMAP service detction and URL schemes.",
    )
    parser.add_argument(
        "-vH",
        "--vhosts",
        action="store_true",
        default=False,
        help=
        "Attempt to scrape hostnames from SSL certificates and add these to the URL queue",
    )
    parser.add_argument(
        "-dB",
        "--dns_brute",
        help=
        "Specify a DNS subdomain wordlist for bruteforcing on wildcard SSL certs",
    )
    parser.add_argument(
        "-uL",
        "--uri_list",
        help="Specify a list of URIs to fetch in addition to the root",
    )
    parser.add_argument(
        "-r",
        "--retries",
        type=int,
        default=0,
        help="Number of retries if a URL fails or timesout",
    )
    parser.add_argument(
        "-tG",
        "--trygui",
        action="store_true",
        default=False,
        help="Try to fetch the page with FireFox when headless fails",
    )
    parser.add_argument(
        "-sF",
        "--smartfetch",
        action="store_true",
        default=False,
        help=
        "Enables smart fetching to reduce network traffic, also increases speed if certain conditions are met.",
    )
    parser.add_argument("-pX",
                        "--proxy",
                        default=None,
                        help="SOCKS5 Proxy in host:port format")

    args = parser.parse_args()

    if len(sys.argv) < 2:
        parser.print_help()
        sys.exit(0)

    # read in the URI list if specificed
    uris = [""]
    if args.uri_list is not None:
        uris = open(args.uri_list, "r").readlines()
        uris.append("")

    if args.input is not None:
        inFile = open(args.input, "r")
        if detectFileType(inFile) == "gnmap":
            hosts = parseGnmap(inFile, args.autodetect)
        elif detectFileType(inFile) == "xml":
            hosts = parsexml(inFile)
        else:
            print("Invalid input file - must be Nmap GNMAP or Nmap XML")

        urls = []

        for host in hosts:
            for port in hosts[host]:
                urls.append(f"http://{host}:{port}")

    elif args.list is not None:
        f = open(args.list, "r")
        lst = f.readlines()
        urls = []
        for url in lst:
            urls.append(url.strip())
    else:
        print("No input specified")
        sys.exit(0)

    # shuffle the url list
    shuffle(urls)

    # read in the subdomain bruteforce list if specificed
    subs = []
    if args.dns_brute is not None:
        subs = open(args.dns_brute, "r").readlines()

    # Fire up the workers
    urlQueue = multiprocessing.Queue()
    manager = multiprocessing.Manager()
    hostsDict = manager.dict()
    workers = []
    hash_basket = {}

    for i in range(args.workers):
        p = multiprocessing.Process(
            target=worker,
            args=(
                urlQueue,
                args.timeout,
                args.verbose,
                args.headless,
                args.autodetect,
                args.vhosts,
                subs,
                hostsDict,
                args.trygui,
                args.smartfetch,
                args.proxy,
                args.browsertype
            ),
        )
        workers.append(p)
        p.start()

    for url in urls:
        urlQueue.put(url)

    for p in workers:
        p.join()
