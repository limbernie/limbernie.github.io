$(document).ready(function() {
	var width = $(window).width();
	backToTop(width);
});

$(window).resize(debounce(function() {
	var width = $(this).width();
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
	var max_width = 977;
	var offset = 345;
	var duration = 300;
	var btt = $('.back-to-top');

	if ( $('.feature-image').length ) offset += $('.feature-image').height();
	if ( $('.notice').length ) offset += $('.notice').height();

	if (width > max_width) {
		var threshold = Math.ceil(offset) - 1;
		$('.post-listing').scroll(function() {
			if ($(this).scrollTop() > threshold) {
				btt.show();
			} else {
				btt.hide();
			}
		});
		btt.click(function() {
			$('.post-listing').animate({
				scrollTop: 0}, duration, function() { $(this).finish(); });
		});
	} else {
		var threshold = 400 + Math.ceil(offset) + 1;
		$(window).scroll(function() {
			if ($(this).scrollTop() > threshold) {
				btt.show();
			} else {
				btt.hide();
			}
		});
		btt.click(function() {
			$('html, body').animate({
				scrollTop: 400}, duration, function() { $(this).finish(); });
		});
	}
}
