"use strict";

exports.customEvent = new CustomEvent("custom");

exports.mkCustomEvent = function (id, data) {
    console.log(new CustomEvent(id, {detail: data, bubbles: true}));
    return new CustomEvent(id, {detail: data});
};


exports.getCustomEventData = function (event) {
    return event.detail;
};
