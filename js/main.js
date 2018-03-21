$(document).ready(function() {

	var max_width = 977;  // trial-n-error
	var width = $(window).width();

	if (width < max_width) backToTop(width);

	function backToTop(width) {
		var offset = 400;
		var duration = 500;

		if ( $('.feature-image').length ) offset += $('.feature-image').height();
		if ( $('.notice').length ) offset += $('.notice').height();

		$(window).scroll(function() {
			if ($(this).scrollTop() > offset + 340) {
				$('.back-to-top').fadeIn(duration);
			} else {
				$('.back-to-top').fadeOut(duration);
			}
		});
		$('.back-to-top').click(function() {
			$('html, body').animate({
				scrollTop: 400}, duration);
		});
	}
});
