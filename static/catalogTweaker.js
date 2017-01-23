$(document).ready(function() {
	$('.expand-text').hover(function() {
		$(this).animate({fontSize: '1.5em'});
	}, function() {
		$(this).animate({fontSize: '1em'});
	});
});
