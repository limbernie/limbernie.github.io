'use strict';

var gulp             = require('gulp');
var cloudinary       = require('gulp-cloudinary-upload');
var gutil            = require('gulp-util');

var cryptojs         = require('crypto-js');
var del              = require('del');
var fs               = require('fs');
var jsdom            = require('jsdom');
const { JSDOM }      = jsdom;
var minimist         = require('minimist');
var through          = require('through2');
var PluginError      = gutil.PluginError;

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

			file.contents = new Buffer(result.join(''));
			this.push(file);
			return callback();
		}
	});
}

var knownOptions = {
    string: 'password',
    string: 'file',
    string: 'folder',
    string: 'path'
};

var options = minimist(process.argv.slice(2), knownOptions);

gulp.task('backup', () => {
	return gulp.src(options.file)
		.pipe(gulp.dest('_protected'));
});

gulp.task('clean', () => {
	return del(options.file);
});

gulp.task('encrypt', () => {
	return gulp.src(options.file)
		.pipe(encrypt(options.password))
		.pipe(gulp.dest('_posts'));
});

gulp.task('upload', () => {
	return gulp.src(options.file ? options.file : options.path.replace(/\/$/, '') + '/*')
		.pipe(cloudinary({
			params: {
				folder: options.folder
			}
		}))
});

gulp.task('default', gulp.series('encrypt', 'backup', 'clean'));
