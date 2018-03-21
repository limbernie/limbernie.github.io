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

	if ( $('.feature-image').length ) offset += $('.feature-image').height();
	if ( $('.notice').length ) offset += $('.notice').height();

	if (width > max_width) {
		$('.post-listing').scroll(function() {
			if ($(this).scrollTop() > offset - 20) {
				$('.back-to-top').fadeIn(duration, function() {
					$('.back-to-top').stop(true, false);
				});
			} else {
				$('.back-to-top').fadeOut(duration, function() {
					$('.back-to-top').stop(true, false);
				});
			}
		});
		$('.back-to-top').click(function() {
			$('.post-listing').animate({
				scrollTop: 0}, duration, function() {
					$('.post-listing').stop(true, false);
			});
		});
	} else {
		$(window).scroll(function() {
			if ($(this).scrollTop() > offset + 340) {
				$('.back-to-top').fadeIn(duration, function() {
					$('.back-to-top').stop(true, false);
				});
			} else {
				$('.back-to-top').fadeOut(duration, function() {
					$('.back-to-top').stop(true, false);
				});
			}
		});
		$('.back-to-top').click(function() {
			$('html, body').animate({
				scrollTop: 400}, duration, function() {
					$('html, body').stop(true, false);
			});
		});
	}
}
