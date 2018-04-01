var max_width = 768;
var em = 16;
var btt = $('.back-to-top');
var sb  = $('.sidebar');
var mn  = $('.menu');
var btn = $('.btn');
var ph  = $('.post-header');
var fi  = $('.feature-image');
var no  = $('.notice');
var c   = $('.content');

var _ml = parseInt(c.css('margin-left').replace(/[^\d.]/g, ''));
var _mr = parseInt(c.css('margin-right').replace(/[^\d.]/g, ''));

$(document).ready(function() {
	var width = $(window).width();
	backToTop(width);

	mn.click(function() {
		menu();
	});
});

$(window).resize(debounce(function() {
	var width = $(window).width();
	backToTop(width);

	_ml = parseInt(c.css('margin-left').replace(/[^\d.]/g, ''));
	_mr = parseInt(c.css('margin-right').replace(/[^\d.]/g, ''));

	c.removeAttr('style');
	sb.removeAttr('style');
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
				 + sb.outerHeight(true)
				 + ph.outerHeight(true)
				 + btn.outerHeight(true);

	if ( fi.length ) offset += fi.outerHeight(true);
	if ( no.length ) offset += no.outerHeight(true);

	if (width < max_width) {
		var threshold = Math.ceil(offset);
		$(window).scroll(function() {
			if ($(this).scrollTop() > threshold) {
				btt.show();
			} else {
				btt.hide();
			}
		});
		btt.click(function() {
			$('html, body').animate({
				scrollTop: 0},
				'slow',
				function() { $(this).finish(); });
		});
	} else {
		$(window).scroll(function() {
			btt.hide();
		});
	}
}

function menu() {
	sidebar();
	//content();
}

function sidebar() {
	var sbm = sb.outerWidth(true);
	sb.toggle();
}

function content() {
	var ml = parseInt(c.css('margin-left').replace(/[^\d.]/g, ''));

	if (ml === _ml) {
		c.css('margin-left' , '20rem');
		c.css('margin-right', '2rem');
	} else {
		c.removeAttr('style');
	}
}
