const std = @import("std");
const Builder = std.build.Builder;

pub fn build(b: *Builder) void {
    const mode = b.standardReleaseOptions();
    const lib = b.addStaticLibrary("rsa-blind-signatures", "src/main.zig");
    lib.setBuildMode(mode);
    lib.install();

    var main_tests = b.addTest("src/main.zig");
    main_tests.addSystemIncludeDir("/usr/local/opt/openssl/include");
    main_tests.addSystemIncludeDir("/usr/local/openssl/include");
    main_tests.addLibPath("/usr/local/opt/openssl/lib");
    main_tests.addLibPath("/usr/local/openssl/lib");
    main_tests.linkSystemLibrary("crypto");
    main_tests.setBuildMode(mode);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&main_tests.step);
}
