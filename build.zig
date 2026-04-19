const std = @import("std");

pub fn build(b: *std.Build) void {
    const optimize = b.standardOptimizeOption(.{});
    const target = b.standardTargetOptions(.{});

    const boringssl_prefix = b.option([]const u8, "boringssl", "Use BoringSSL from this install prefix instead of OpenSSL");

    const translate_c = b.addTranslateC(.{
        .root_source_file = b.path("src/openssl.h"),
        .target = target,
        .optimize = optimize,
    });

    if (boringssl_prefix) |prefix| {
        translate_c.addSystemIncludePath(.{ .cwd_relative = b.fmt("{s}/include", .{prefix}) });
    } else {
        translate_c.linkSystemLibrary("libcrypto", .{});
    }

    const ssl_module = translate_c.createModule();

    const mod = b.addModule("blind_rsa_signatures", .{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "ssl", .module = ssl_module },
        },
    });

    const lib = b.addLibrary(.{
        .name = "blind-rsa-signatures",
        .root_module = mod,
        .linkage = .static,
    });
    b.installArtifact(lib);

    const main_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "ssl", .module = ssl_module },
            },
        }),
    });

    if (boringssl_prefix) |prefix| {
        main_tests.root_module.addLibraryPath(.{ .cwd_relative = b.fmt("{s}/lib", .{prefix}) });
        main_tests.root_module.linkSystemLibrary("crypto", .{ .use_pkg_config = .no });
        main_tests.root_module.linkSystemLibrary("c++", .{ .use_pkg_config = .no });
    } else {
        main_tests.root_module.linkSystemLibrary("libcrypto", .{});
    }

    const run_main_tests = b.addRunArtifact(main_tests);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&run_main_tests.step);
}
