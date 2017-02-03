$(document).ready(function() {
	$('a').hover(function() {
		$(this).animate({fontSize: '1.3em'}, 800);
	}, function() {
		$(this).animate({fontSize: '1em'}, 1000);
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
	admin += "><br></div><br><br>"
};
