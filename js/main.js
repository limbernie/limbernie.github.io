var max_width = 977;  // trial-n-error

$(document).ready(function() {

	width = $(window).width();
	backToTop(width);
});

$(window).resize(function() {
	backToTop($(window).width());
});


function backToTop(width) {
	var offset = 400;
	var duration = 500;
	var btt = $('.back-to-top');

	if ( $('.feature-image').length ) offset += $('.feature-image').height();
	if ( $('.notice').length ) offset += $('.notice').height();

	if (width > max_width) {
		$('.post-listing').scroll(function() {
			if ($(this).scrollTop() > Math.ceil(offset - 56)) {
				btt.fadeIn(duration, function() {
					btt.stop(true, true);
				});
			} else {
				btt.fadeOut(duration, function() {
					btt.stop(true, true);
				});
			}
		});
		btt.click(function() {
			$('.post-listing').animate({
				scrollTop: 0}, duration, function() {
					$('.post-listing').stop(true, false);
			});
		});
	} else {
		$(window).scroll(function() {
			if ($(this).scrollTop() > offset + 340) {
				btt.fadeIn(duration, function() {
					btt.stop(true, true);
				});
			} else {
				btt.fadeOut(duration, function() {
					btt.stop(true, true);
				});
			}
		});
		btt.click(function() {
			$('html, body').animate({
				scrollTop: 0}, duration, function() {
					$('html, body').stop(true, false);
			});
		});
	}
}
