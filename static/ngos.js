$(document).ready(function() {
	var admin = "<div id='admin'><h2>The administrator of this category is "
	admin += $('#admin-name').text()
	admin += "</h2><img src="
	admin += $('#admin-picture').text()
	admin += "><br></div><br><br>"
	$('.continent-expand-text:last-of-type').append(admin);
	
	var ngos = []
	$('.ngo-name').each(function() {
		ngos.push($(this).text());
	})
	var ngo;
	for (ngo in ngos) {
		var wikiRequestURL = ("https://en.wikipedia.org/w/api.php?format=json&formatversion=2&action=query&prop=extracts&exintro=&explaintext=&titles=" + ngos[ngo] + "&callback=wikiCallback");
		$.ajax({url: wikiRequestURL, dataType: 'jsonp'}).done(function(response) {
			ngoName = response.query.pages[0].title
			var ngoID = '#' + ngoName.replace(/ /g, '-');
			$(ngoID).append(response.query.pages[0].extract);
		});
	};
});
//if (window.location.href.indexOf('ngos'))
