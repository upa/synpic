

function num2rgb(num) {
    v = Math.floor(num * 256);
    return "#" + v.toString(16) + v.toString(16) + v.toString(16);
}

function prob2class(prob) {
    if (prob >= 95) {
	return "danger";
    } else if (prob >= 80) {
	return "warn";
    } else {
	return "normal";
    }
}

function draw_syn_picture(synpic, svgid) {
    
    var box_width = 10;
    
    draw = SVG(svgid).size(box_width * 100, box_width * 5);

    for (var y = 0, l1 = synpic.length; y < l1; y++) {
	for (var x = 0, l2 = synpic[y].length; x < l2; x++) {
	    draw.rect(10, 10).move(box_width * y, box_width * x)
		.fill(num2rgb(synpic[y][x]));
	}
    }
}

function add_syn_picture(addr, probability, picture) {

    var id = String(Math.floor(Math.random() * 10000));
    frameid = "frame-" + id;
    svgid = "svg-" + id;

    probclass = prob2class(probability);

    var frame = $("<div>", { addClass: "frame clearfix" });
    frame.attr("id", frameid);
    frame.prependTo("#pictures").hide().fadeIn(300);
    //frame.prependTo("#pictures");
    frame.append("<svg class='synpic' id='" + svgid + "'>");
    frame.append("<div class='description'> Address: " + addr + "<br/>" +
		 "Probabirity of Malicious: " +
		 "<span class='" + probclass + "'>" + probability + "% " +
		 "</span></div>");

    draw_syn_picture(picture, svgid);

}


function display_syn_picture(jsondata) {

    max_frame_num = 20;

    prob = jsondata["probability"];
    prob = Math.floor(prob * Math.pow(10, 2)) / Math.pow(10, 2);
    add_syn_picture(jsondata["addr"], prob, jsondata["picture"]);

    if ($(".frame").length > max_frame_num) {
	$($(".frame")[$(".frame").length-1]).remove(); 
    }
}


// web socket part



//var uri = "ws://" + location.host + ":8081";
var uri = "ws://127.0.0.1:8081";
var websocket = null;


function init() {
    console.log("start to init websocket");
    open();
}

function open() {
    if (websocket == null) {
	websocket = new WebSocket(uri);
	websocket.onopen = onOpen;
	websocket.onmessage = onMessage;
	websocket.onclose = onClose;
	websocket.onerror = onError;
    }
}

function onOpen(event) {
    console.log("success to connect " + uri);
}

function onMessage(event) {
    console.log(event.data);
    display_syn_picture(JSON.parse(event.data))
}

function onError(event) {
    console.log("websocket error:" + event.data);
}

function onClose(event) {
    console.log("websocket closed. retry connect.");
    websocket = null;
    setTimeout("open()", 3000);
}


