//go:build darwin

package main

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework AppKit
#import <AppKit/AppKit.h>
#include <stdlib.h>

typedef struct {
	void* data;
	int length;
} PNGData;

PNGData sfSymbolToPNG(const char* name, double pointSize) {
	PNGData result = {NULL, 0};
	@autoreleasepool {
		NSImage *img = [NSImage imageWithSystemSymbolName:
			[NSString stringWithUTF8String:name]
			accessibilityDescription:nil];
		if (!img) return result;

		NSImageSymbolConfiguration *cfg = [NSImageSymbolConfiguration
			configurationWithPointSize:pointSize
			weight:NSFontWeightMedium];
		img = [img imageWithSymbolConfiguration:cfg];

		NSData *tiff = [img TIFFRepresentation];
		if (!tiff) return result;

		NSBitmapImageRep *rep = [NSBitmapImageRep imageRepWithData:tiff];
		if (!rep) return result;

		NSData *png = [rep representationUsingType:NSBitmapImageFileTypePNG
										properties:@{}];
		if (png) {
			result.data = malloc(png.length);
			memcpy(result.data, png.bytes, png.length);
			result.length = (int)png.length;
		}
	}
	return result;
}
*/
import "C"

import "unsafe"

func makeIcon() []byte {
	cName := C.CString("eye")
	defer C.free(unsafe.Pointer(cName))

	result := C.sfSymbolToPNG(cName, C.double(16))
	if result.data == nil {
		return nil
	}
	defer C.free(result.data)

	return C.GoBytes(result.data, result.length)
}
