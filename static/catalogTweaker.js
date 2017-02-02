$(document).ready(function() {
	$('.expand-text').hover(function() {
		$(this).animate({fontSize: '1.2em'}, 200);
	}, function() {
		$(this).animate({fontSize: '1em'}, 800);
	});
	$('.ngo-focus').hover(function() {
		$(this).animate({fontSize: '1.2em'}, 200);
	}, function() {
		$(this).animate({fontSize: '1em'}, 800);
	});
	if (window.location.href.indexOf('ngos')) {
		$('.continent-expand-text:last-of-type').append(admin);
	}
});

if (window.location.href.indexOf('ngos')) {
	var admin = "<div id='admin'><h2>The administrator of this category is "
	admin += admin_name
	admin += "</h2><img src="
	admin += admin_picture
	admin += "></div><br><br>"
};
