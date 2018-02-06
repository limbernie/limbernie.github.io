$(document).ready(function() {
	var offset = 250;
	var duration = 500;
	if ($(window).width() > 977) {
		$('.post-listing').scroll(function() {
			if ($(this).scrollTop() > offset) {
				$('.back-to-top').fadeIn(duration);
			} else {
				$('.back-to-top').fadeOut(duration);
			}
		});
		$('.back-to-top').click(function() {
			$('.post-listing').animate({
				scrollTop: 0}, 600);
		});
	} else {
		$(window).scroll(function() {
			if ($(this).scrollTop() > offset) {
				$('.back-to-top').fadeIn(duration);
			} else {
				$('.back-to-top').fadeOut(duration);
			}
		});
		$('.back-to-top').click(function() {
			$('html, body').animate({
				scrollTop: 0}, 600);
		});
	}
});
