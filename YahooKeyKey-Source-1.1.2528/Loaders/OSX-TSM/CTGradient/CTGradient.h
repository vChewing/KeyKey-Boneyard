//
//  CTGradient.h
//
//  Created by Chad Weider on 2/14/07.
//  Copyright (c) 2007 Chad Weider.
//  Some rights reserved: <http://creativecommons.org/licenses/by/2.5/>
//
//  Version: 1.6

#import <Cocoa/Cocoa.h>

typedef struct _CTGradientElement {
  float red, green, blue, alpha;
  float position;

  struct _CTGradientElement *nextElement;
} CTGradientElement;

typedef enum _CTBlendingMode {
  CTLinearBlendingMode,
  CTChromaticBlendingMode,
  CTInverseChromaticBlendingMode
} CTGradientBlendingMode;

@interface CTGradient : NSObject <NSCopying, NSCoding> {
  CTGradientElement *elementList;
  CTGradientBlendingMode blendingMode;

  CGFunctionRef gradientFunction;
}

+ (id)gradientWithBeginningColor:(NSColor *)begin endingColor:(NSColor *)end;

+ (id)aquaSelectedGradient;
+ (id)aquaNormalGradient;
+ (id)aquaPressedGradient;

+ (id)unifiedSelectedGradient;
+ (id)unifiedNormalGradient;
+ (id)unifiedPressedGradient;
+ (id)unifiedDarkGradient;

+ (id)sourceListSelectedGradient;
+ (id)sourceListUnselectedGradient;

+ (id)rainbowGradient;
+ (id)hydrogenSpectrumGradient;

- (CTGradient *)gradientWithAlphaComponent:(float)alpha;

- (CTGradient *)addColorStop:(NSColor *)color
                  atPosition:
                      (float)position;  // positions given relative to [0,1]
- (CTGradient *)removeColorStopAtIndex:(unsigned)index;
- (CTGradient *)removeColorStopAtPosition:(float)position;

- (CTGradientBlendingMode)blendingMode;
- (NSColor *)colorStopAtIndex:(unsigned)index;
- (NSColor *)colorAtPosition:(float)position;

- (void)drawSwatchInRect:(NSRect)rect;
- (void)fillRect:(NSRect)rect angle:(float)angle radius:(float)radius;
- (void)radialFillRect:(NSRect)rect;
- (void)fillBezierPath:(NSBezierPath *)path angle:(float)angle;
- (void)radialFillBezierPath:(NSBezierPath *)path;

@end
