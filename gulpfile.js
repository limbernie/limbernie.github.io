'use strict';

var gulp          = require('gulp');
var gutil         = require('gulp-util');
var del           = require('del');

var cryptojs      = require('crypto-js');
var jsdom         = require('jsdom');
const { JSDOM }   = jsdom;

var minimist      = require('minimist');
var fs            = require('fs');
var through       = require('through2');
var PluginError   = gutil.PluginError;

function hasProtect(frontMatter) {
	return frontMatter.match(/protect: true/) ? 1 : 0;
}

function encrypt(password) {
	return through.obj(function(file, encoding, callback) {
		if (file.isNull() || file.isDirectory()) {
	  		this.push(file);
			return callback();
		}

		// check for the presence of index.html
		var index = './_site/' + file.relative.split('-').slice(3).join('-').replace('.md', '') + '/index.html';
		if (!fs.existsSync(index)) {
			this.emit('error', new PluginError({
				plugin: 'Protect',
				message: 'File "' + index + '" not found. ' + "Did you run `bundle exec jekyll serve --drafts' first?"
			}));
			return callback();
		}

		if (file.isBuffer()) {
			var delimiter = '---',
			chunks = String(file.contents).split(delimiter),
			frontMatter = chunks[1];
			
			if (!hasProtect(frontMatter)) {
				this.emit('error', new PluginError({
					plugin: 'Protect',
					message: 'Front Matter "protect: true" not found.'
				}));
			}
			
			var dom = new JSDOM(String(fs.readFileSync(index))),
				originalBody = dom.window.document.querySelector('.post-content').outerHTML,
				encryptedBody = cryptojs.AES.encrypt(originalBody, password),
				hmac = cryptojs.HmacSHA256(encryptedBody.toString(), cryptojs.SHA256(password).toString()).toString(),
				encryptedFrontMatter = 'encrypted: ' + hmac + encryptedBody,
				result = [ delimiter, frontMatter, encryptedFrontMatter, '\n', delimiter ];
			
			console.log(originalBody);
			
			file.contents = new Buffer(result.join(''));
			this.push(file);
			return callback();
		}
	});
}

var knownOptions = {
    string: 'password',
    string: 'file'
};

var options = minimist(process.argv.slice(2), knownOptions);

gulp.task('backup', () => {
	return gulp.src(options.file)
		.pipe(gulp.dest('_protected'))
});

gulp.task('clean', () => {
	return del(options.file)
});

gulp.task('encrypt', () => {
	return gulp.src(options.file)
		.pipe(gulp.dest('_protected'))
		.pipe(encrypt(options.password))
		.pipe(gulp.dest('_posts'))
});

gulp.task('default', gulp.series('encrypt', 'backup', 'clean'));
