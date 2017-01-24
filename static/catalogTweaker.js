$(document).ready(function() {
	$('.expand-text').hover(function() {
		$(this).animate({fontSize: '1.5em'}, 200);
	}, function() {
		$(this).animate({fontSize: '1em'}, 1000);
	});
});
