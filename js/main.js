var max_width = 768;
var btt = $('.back-to-top');
var mn = $('.menu');

$(document).ready(function() {
	var width = $(window).width();
	backToTop(width);
	mn.click(function() {
		move();
	});
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
	var offset = 65
				 + $('.sidebar').outerHeight(true)
				 + $('.post-header').outerHeight(true)
				 + $('.btn').outerHeight(true);

	if ( $('.feature-image').length ) offset += $('.feature-image').outerHeight(true);
	if ( $('.notice').length ) offset += $('.notice').outerHeight(true);

	if (width < max_width) {
		var threshold = Math.ceil(offset);
		$(window).scroll(function() {
			if ($(this).scrollTop() > threshold) {
				btt.fadeIn('slow');
			} else {
				btt.fadeOut('slow');
			}
		});
		btt.click(function() {
			$('html, body').animate({
				scrollTop: 0},
				'fast',
				function() { $(this).finish(); });
		});
	} else {
		$(window).scroll(function() {
			btt.hide();
		});
	}
}

function move() {
	var sb = $('.sidebar');
	var sbm = sb.outerWidth(true) - 20;

	sb.animate({'margin-left' : '-' + sbm + 'px'}, 'slow');
}
