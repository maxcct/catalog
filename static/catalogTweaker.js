$(document).ready(function() {
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
