/*
 * Copyright 2014 Michinobu Maeda.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
var tileCount = 4;
var tileSize = 80;
var frameSize = tileSize * tileCount;
var tileBorderWidth = 2;
var pos = Array();
var gap = tileCount * tileCount - 1;
var timer = 0;
var isActive = false;
var imagesrc = "/html/numbers1.png";

function initPuzzle(images) {

    $('#puzzle-frame').height(frameSize);
    $('#puzzle-frame').width(frameSize);
    $('#puzzle-frame').after('<div id="images"></div>');
    
    imagesrc = images[0];
    for (var i = 0; i < images.length; ++i) {
        if (images[i] == null) {
        } else {
            $('#images').append(
                '<img class="tn" id="image' + i + '" src="' +
                images[i] + '" alt="image ' + (i + 1) + '"/>'
            );
            $('#image'+i).on('click', function () {
                imagesrc = $(this).attr('src');
                setImage();
            });
        }
    }

    for (var i = 0; i < (tileCount * tileCount); ++i) {

        $('#puzzle-frame').append(
            '<div class="tile" id="t' + i +'"><img id="i' + i + 
            '" src="/html/numbers1.png" alt="Tile ' + i + 
            '" onclick="onTileClick(' + i + ')"/></div>'
        );
        pos[i] = i;
    }

    setImage();
}

function onTileClick(tile) {
    
    if (isActive != true) { return; }

    if (swapTiles(tile)) {

        updatePosition();

        if (isComplete()) {
            active = false;

            timer = window.setTimeout(function() {
                setImage();
            }, 1000);
        }
    }
}

function setImage() {

    if (timer) { window.clearTimeout(timer); }
    updateImage(0);

    timer = window.setTimeout(function() {
        splitImage();
    }, 2000);
}

function splitImage() {

    updateImage(tileBorderWidth);

    timer = window.setTimeout(function() {
        createGap();
    }, 2000);
}

function createGap() {

    $('#i'+gap).css({opacity: 0.0});
    $('#t'+gap).css({border: 'none'});

    timer = window.setTimeout(function() {
        shaffleTiles();
    }, 2000);
}

function shaffleTiles() {

    var shaffleCount = 0;

    timer = window.setInterval(function() {

        ++ shaffleCount;
        while (false == swapTiles(Math.floor(Math.random() * 16))) {}
        updatePosition();

        if (100 < shaffleCount) {
            window.clearTimeout(timer);
            isActive = true;
        }
    }, 10);
}

function updateImage(borderWidth) {
    
    for (var i = 0; i < (gap + 1); ++i) {

        pos[i] = i;

        $('#t'+i).css({
            width : '' + tileSize + 'px',
            height: '' + tileSize + 'px',
            margin: '' + (Math.floor(pos[i] / tileCount) * tileSize) + 'px 0 0 ' +
                    (pos[i] % tileCount * tileSize) + 'px',
            borderTop   : 'solid ' + borderWidth + 'px #ddd',
            borderRight : 'solid ' + borderWidth + 'px #666',
            borderBottom: 'solid ' + borderWidth + 'px #666',
            borderLeft  : 'solid ' + borderWidth + 'px #ddd'
        });

        $('#i'+i).attr('src', imagesrc);
        $('#i'+i).css({
            width : '' + frameSize + 'px',
            height: '' + frameSize + 'px',
            margin: '' + (Math.floor(i / tileCount) * tileSize * -1 - borderWidth) + 'px 0 0 ' +
                    (i % tileCount * tileSize * -1 - borderWidth) + 'px',
            opacity: 1.0,
            visibility: 'visible'
        });
    }
}

function updatePosition() {

    for (var i = 0; i < tileCount * tileCount; ++i) {
        $('#t'+i).css({
            marginTop : "" + (Math.floor(pos[i] / tileCount) * tileSize) + "px",
            marginLeft: "" + (pos[i] % tileCount * tileSize) + "px",
        });
    }
}

function isComplete() {
    for (var i = 0; i < tileCount * tileCount; ++i) {
        if (i != pos[i]) { return false; }
    }
    return true;
}

function swapTiles(tile) {

    var delta = 0;

    if (tile < 0) { return false; }

    if ((Math.floor(pos[tile] / tileCount)) == (Math.floor(pos[gap] / tileCount))) {
        delta = (pos[tile] < pos[gap]) ? -1 : 1;            
    } else if ((pos[tile] % tileCount) == (pos[gap] % tileCount)) {
        delta = (pos[tile] < pos[gap]) ? -tileCount : tileCount;            
    }
    
    if (delta == 0) { return false; }
    
    var stop = pos[tile];
    
    for (var i = pos[gap]; i != stop; i += delta) {
        for (var j = 0; j < (tileCount * tileCount); ++j) {
            if (pos[j] == (i + delta)) {
                pos[j] = i;
                break;
            }
        }
        pos[gap] = i + delta;
    }
        
    return true;
}
