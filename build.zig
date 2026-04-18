const std = @import("std");

pub fn build(b: *std.Build) void {
    const optimize = b.standardOptimizeOption(.{});
    const target = b.standardTargetOptions(.{});

    const ssl = b.addTranslateC(.{
        .root_source_file = b.path("src/openssl.h"),
        .target = target,
        .optimize = optimize,
    }).createModule();
    ssl.linkSystemLibrary("crypto", .{});

    const root_module = b.addModule("rsa-blind-signatures", .{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    root_module.addImport("ssl", ssl);

    const lib = b.addLibrary(.{
        .name = "rsa-blind-signatures",
        .root_module = root_module,
        .linkage = .static,
    });
    b.installArtifact(lib);

    const main_tests = b.addTest(.{
        .root_module = root_module,
    });

    const run_main_tests = b.addRunArtifact(main_tests);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&run_main_tests.step);
}
