function debounce(o,t,i){var n;return function(){var c=this,e=arguments,s=function(){n=null,i||o.apply(c,e)},l=i&&!n;clearTimeout(n),n=setTimeout(s,t),l&&o.apply(c,e)}}function backToTop(o){if(0!==$("h3").length){var t=$("h3")[0],i=Math.ceil(t.offsetTop);$(window).scroll(function(){$(this).scrollTop()>i?btt.show():btt.hide()}),btt.click(function(){$("html, body").animate({scrollTop:0},"fast",function(){$(this).finish()})})}}function draw(){sb.toggle("slide",{direction:"left"},"fast"),overlay(),toggle()}function overlay(){"hidden"===ol.css("visibility")?(ol.css({visibility:"visible",opacity:0}).animate({opacity:1},"fast"),ol.on("click",function(){draw()}),b.css("overflow-y","hidden")):(ol.css({visibility:"hidden",opacity:1}).animate({opacity:0},"fast"),ol.off("click"),b.css("overflow-y","auto"))}function toggle(){var o="fa-ellipsis-",t="fas "+n,i=o+"h",n=o+"v";ic.attr("class")===t?ic.toggleClass(n+" "+i):ic.toggleClass(i+" "+n)}function stopScroll(o){!0===o?b.on("touchmove",function(o){o.preventDefault(),o.stopPropagation()}):b.off("touchmove")}var btt=$(".back-to-top"),sb=$(".sidebar"),mn=$(".menu"),btn=$(".btn"),ph=$(".post-header"),fi=$(".feature-image"),no=$(".notice"),ol=$(".overlay"),b=$("body"),ic=mn.find("i");$(document).ready(function(){backToTop($(window).width()),mn.click(function(){draw()})}),$(window).resize(debounce(function(){backToTop($(window).width()),"none"==sb.css("display")&&sb.removeAttr("style")},500));
