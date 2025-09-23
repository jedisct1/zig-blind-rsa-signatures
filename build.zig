const std = @import("std");

const CryptoLib = enum { openssl, boringssl };

const crypto_lib: CryptoLib = .openssl;

pub fn build(b: *std.Build) void {
    const optimize = b.standardOptimizeOption(.{});
    const target = b.standardTargetOptions(.{});
    const lib = b.addLibrary(.{
        .name = "rsa-blind-signatures",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
        .linkage = .static,
    });
    b.installArtifact(lib);

    var main_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    if (crypto_lib == .openssl) {
        main_tests.root_module.addSystemIncludePath(.{ .cwd_relative = "/usr/local/opt/openssl/include" });
        main_tests.root_module.addSystemIncludePath(.{ .cwd_relative = "/usr/local/openssl/include" });
        main_tests.root_module.addSystemIncludePath(.{ .cwd_relative = "/opt/homebrew/opt/openssl@3/include" });
        main_tests.root_module.addLibraryPath(.{ .cwd_relative = "/usr/local/opt/openssl/lib" });
        main_tests.root_module.addLibraryPath(.{ .cwd_relative = "/usr/local/openssl/lib" });
        main_tests.root_module.addLibraryPath(.{ .cwd_relative = "/opt/homebrew/opt/openssl@3/lib" });
    } else {
        main_tests.root_module.addSystemIncludePath(.{ .cwd_relative = "/Users/j/src/boringssl/install/include" });
        main_tests.root_module.addLibraryPath(.{ .cwd_relative = "/Users/j/src/boringssl/install/lib" });
    }
    main_tests.root_module.linkSystemLibrary("crypto", .{});

    const run_main_tests = b.addRunArtifact(main_tests);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&run_main_tests.step);
}
