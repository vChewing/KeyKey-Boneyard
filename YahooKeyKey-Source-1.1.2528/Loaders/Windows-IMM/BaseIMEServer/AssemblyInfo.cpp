using namespace System;
using namespace System::Reflection;
using namespace System::Runtime::CompilerServices;
using namespace System::Runtime::InteropServices;
using namespace System::Security::Permissions;

//
// General Information about an assembly is controlled through the following
// set of attributes. Change these attribute values to modify the information
// associated with an assembly.
//
[assembly:AssemblyTitleAttribute("BaseIMEServer")];
[assembly:AssemblyDescriptionAttribute("Yahoo! KeyKey Input Method Server")];
[assembly:AssemblyConfigurationAttribute("")];
[assembly:AssemblyCompanyAttribute("Yahoo! Taiwan")];
[assembly:AssemblyProductAttribute("Yahoo! KeyKey")];
[assembly:AssemblyCopyrightAttribute(
              "Copyright (c) 2008-2010 Yahoo! Taiwan. All Rights Reserved.")];
[assembly:AssemblyTrademarkAttribute("")];
[assembly:AssemblyCultureAttribute("")];

//
// Version information for an assembly consists of the following four values:
//
//      Major Version
//      Minor Version
//      Build Number
//      Revision
//
// You can specify all the value or you can default the Revision and Build
// Numbers by using the '*' as shown below:

[assembly:AssemblyVersionAttribute("1.1.2528.0")];

[assembly:ComVisible(false)];

[assembly:CLSCompliantAttribute(true)];

[assembly:SecurityPermission(SecurityAction::RequestMinimum,
                             UnmanagedCode = true)];
