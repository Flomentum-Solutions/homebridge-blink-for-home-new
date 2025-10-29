const {describe, expect, test} = require('@jest/globals');
const {formatFfmpegHeaders} = require('./proxy');

describe('proxy helpers', () => {
    test('formatFfmpegHeaders()', () => {
        const formatted = formatFfmpegHeaders({Authorization: 'Bearer token', 'X-Test': '1'});
        expect(formatted).toContain('Authorization: Bearer token');
        expect(formatted).toContain('X-Test: 1');
        expect(formatted.endsWith('\r\n')).toBe(true);
    });
    test('formatFfmpegHeaders(empty)', () => {
        expect(formatFfmpegHeaders()).toBeUndefined();
        expect(formatFfmpegHeaders({})).toBeUndefined();
        expect(formatFfmpegHeaders({Authorization: null})).toBeUndefined();
    });
});
