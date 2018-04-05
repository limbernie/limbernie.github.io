var max_width = 768;
var btt = $('.back-to-top');
var sb  = $('.sidebar');
var mn  = $('.menu');
var ic  = mn.find('i');
var btn = $('.btn');
var ph  = $('.post-header');
var fi  = $('.feature-image');
var no  = $('.notice');
var ol  = $('.overlay');
var b   = $('body');

$(document).ready(function() {
	var width = $(window).width();
	backToTop(width);

	mn.click(function() {
		draw();
	});
});

$(window).resize(debounce(function() {
	var width = $(window).width();
	backToTop(width);
	if (sb.css('display') == 'none') sb.removeAttr('style');
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
				'fast',
				function() { $(this).finish(); });
		});
	} else {
		$(window).scroll(function() {
			btt.hide();
		});
	}
}

function draw() {
	sb.toggle('slide', { direction: 'left' }, 'fast');
	overlay();
	toggle();
}

function overlay() {
	if (ol.css('visibility') === 'hidden') {
		ol.css({'visibility':'visible','opacity':0.0}).animate({'opacity':1.0}, 'fast');
		ol.on('click', function() { draw(); });
		b.css('overflow-y', 'hidden');
	} else {
		ol.css({'visibility':'hidden','opacity':1.0}).animate({'opacity':0.0}, 'fast');
		ol.off('click');
		b.css('overflow-y', 'auto');
	}
}

function toggle() {
	var e = 'fa-ellipsis-';
	var s = 'fas' + ' ' + v;
	var h = e + 'h';
	var v = e + 'v';

	if (ic.attr('class') === s)
		ic.toggleClass(v + ' ' + h);
	else
		ic.toggleClass(h + ' ' + v);
}
