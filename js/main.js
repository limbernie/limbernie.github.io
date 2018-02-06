$(document).ready(function() {
	var size = 977;
	var duration = 500;
	if ($(window).width() > size) {
		var offset = 400;
		$('.post-listing').scroll(function() {
			if ($(this).scrollTop() > offset) {
				$('.back-to-top').fadeIn(duration);
			} else {
				$('.back-to-top').fadeOut(duration);
			}
		});
		$('.back-to-top').click(function() {
			$('.post-listing').animate({
				scrollTop: 0}, duration);
		});
	} else {
		$(window).scroll(function() {
			var offset = 900;
			if ($(this).scrollTop() > offset) {
				$('.back-to-top').fadeIn(duration);
			} else {
				$('.back-to-top').fadeOut(duration);
			}
		});
		$('.back-to-top').click(function() {
			$('html, body').animate({
				scrollTop: 0}, duration);
		});
	}
});
