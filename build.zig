const std = @import("std");

pub fn build(b: *std.Build) void {
    const optimize = b.standardOptimizeOption(.{});
    const target = b.standardTargetOptions(.{});
    const lib = b.addStaticLibrary(.{
        .name = "rsa-blind-signatures",
        .root_source_file = .{ .path = "src/main.zig" },
        .optimize = optimize,
        .target = target,
    });
    b.installArtifact(lib);

    var main_tests = b.addTest(.{ .root_source_file = .{ .path = "src/main.zig" } });
    main_tests.addSystemIncludePath(.{ .path = "/usr/local/opt/openssl/include" });
    main_tests.addSystemIncludePath(.{ .path = "/usr/local/openssl/include" });
    main_tests.addSystemIncludePath(.{ .path = "/opt/homebrew/opt/openssl@1.1/include" });
    main_tests.addLibraryPath(.{ .path = "/usr/local/opt/openssl/lib" });
    main_tests.addLibraryPath(.{ .path = "/usr/local/openssl/lib" });
    main_tests.addLibraryPath(.{ .path = "/opt/homebrew/opt/openssl@1.1/lib" });
    main_tests.linkSystemLibrary("crypto");

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&main_tests.step);
}
