$(document).ready(function() {
	var width = $(window).width();
	backToTop(width);
});

$(window).resize(debounce(function() {
	var width = $(window).width();
	backToTop(width);
}, 500));

function debounce(func, wait, immediate) {
	var timeout;
	return function() {
		var context = this, args = arguments;
		var later = function() {
			timeout = null;
			if (!immediate) func.apply(context, args);
		};
		var callNow = immediate && !timeout;
		clearTimeout(timeout);
		timeout = setTimeout(later, wait);
		if (callNow) func.apply(context, args);
	};
};

function backToTop(width) {
	var max_width = 977;  // trial-n-error
	var offset = 400;
	var duration = 500;
	var btt = $('.back-to-top');

	if ( $('.feature-image').length ) offset += $('.feature-image').height();
	if ( $('.notice').length ) offset += $('.notice').height();

	if (width > max_width) {
		$('.post-listing').scroll(function() {
			if ($(this).scrollTop() > Math.ceil(offset - 56)) {
				btt.fadeIn(duration);
			} else {
				btt.fadeOut(duration);
			}
		});
		btt.click(function() {
			$('.post-listing').animate({
				scrollTop: 0}, duration);
		});
	} else {
		$(window).scroll(function() {
			if ($(this).scrollTop() > offset + 340) {
				btt.fadeIn(duration);
			} else {
				btt.fadeOut(duration);
			}
		});
		btt.click(function() {
			$('html, body').animate({
				scrollTop: 0}, duration);
		});
	}
}
