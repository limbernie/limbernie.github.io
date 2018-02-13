$(document).ready(function() {

	var max_width = 977;  // trial-n-error
	var width = $(window).width();

	backToTop(width);

	$(window).resize(function() {
		if($(this).width() != width) {
			width = $(this).width();
			backToTop(width);
		}
		if($(this).width() > max_width)	{
			$('.lineno').show();
		} else {
			$('.lineno').hide();
		}
	});

	function backToTop(width) {

		var offset = 400;
		var duration = 500;

		if (width > max_width) {
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
				if ($(this).scrollTop() > offset + 500) {
					$('.back-to-top').fadeIn(duration);
				} else {
					$('.back-to-top').fadeOut(duration);
				}
			});
			$('.back-to-top').click(function() {
				$('html, body').animate({
					scrollTop: offset}, duration);
			});
		}
	}
	$(function() {
		$('.preview').miniPreview();
	});
});
