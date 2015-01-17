
	function popUp(e,src)
	{
	    x = e.clientX;
	    y = e.clientY;

	    var img = document.createElement("img");
	    img.src = src;
	    img.setAttribute("class","popUp");
	    img.setAttribute("style","position:fixed;left:"+(x+15)+";top:"+0+";background-color:white");
	    //img.setAttribute("onmouseout","clearPopup(event)")
	    // This next line will just add it to the <body> tag
	    document.body.appendChild(img);
	}

	function clearPopup()
	{
	    var popUps = document.getElementsByClassName('popUp');
	    while(popUps[0]) {
	        popUps[0].parentNode.removeChild(popUps[0]);
	    }
	}
	