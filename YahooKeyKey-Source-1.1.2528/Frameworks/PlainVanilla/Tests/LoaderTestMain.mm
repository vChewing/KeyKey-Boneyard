//
// LoaderTestMain.mm
//
// Copyright (c) 2007-2010 Lukhnos D. Liu (http://lukhnos.org)
//
// Permission is hereby granted, free of charge, to any person
// obtaining a copy of this software and associated documentation
// files (the "Software"), to deal in the Software without
// restriction, including without limitation the rights to use,
// copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following
// conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
// OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
// HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
// WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
// OTHER DEALINGS IN THE SOFTWARE.
//

#import <Cocoa/Cocoa.h>

#include "TestPlainVanillaLoader.h"

int main(int argc, char* argv[]) {
  id pool = [NSAutoreleasePool new];
  NSApplicationLoad();

  int ret = 1;

  if (argc > 2) {
    fprintf(stderr, "using analysis mode\n");
  }

  id pool2 = [NSAutoreleasePool new];

  fprintf(stderr, "press any key to start\n");
  fgetc(stdin);

  if (argc > 1)
    ret = TestPlainVanillaLoader(argv[1]);
  else
    fprintf(stderr, "usage: TestPlainVanillaLoader path\n");

  [pool2 drain];
  [pool2 release];

  if (argc > 2) {
    fprintf(stderr, "waiting for analysis mode to end\n");
    while (1) {
    }
  }

  [pool drain];
  [pool release];

  return ret;
}
