$(document).ready(function() {
	$('.expand-text').hover(function() {
		$(this).animate({fontSize: '1.2em'}, 200);
	}, function() {
		$(this).animate({fontSize: '1em'}, 800);
	});
	$('.menu-expand-text:last-of-type').append(owner);
});

var owner = "<div id='proprietor'><h2>The proprietor of this establishment is "
owner += owner_name
owner += "</h2><img src="
owner += owner_picture
owner += "></div><br><br>"
