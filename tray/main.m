#import <Cocoa/Cocoa.h>
#import <ServiceManagement/ServiceManagement.h>
#import <UniformTypeIdentifiers/UniformTypeIdentifiers.h>
#include <signal.h>
#include <spawn.h>
#include <sys/wait.h>

@interface AppDelegate : NSObject <NSApplicationDelegate, NSURLSessionDataDelegate>
@property (strong) NSStatusItem *statusItem;
@property (assign) pid_t serverPID;
@property (strong) NSTimer *healthTimer;
@property (strong) NSWindow *benchWindow;
@property (strong) NSMutableData *benchBuffer;
@property (copy) NSString *latestVersion;
@property (assign) BOOL updateAvailable;
@end

@implementation AppDelegate

- (void)applicationDidFinishLaunching:(NSNotification *)notification {
    // Prevent App Nap — keeps timers and network responsive while backgrounded.
    // Uses NSActivityLatencyCritical (not IdleSystemSleepDisabled) so battery is unaffected.
    [[NSProcessInfo processInfo] beginActivityWithOptions:NSActivityLatencyCritical
                                                  reason:@"Proving service must respond to relay requests"];
    
    // Listen for system wake to immediately reconnect relay
    [[[NSWorkspace sharedWorkspace] notificationCenter] addObserver:self
                                                           selector:@selector(handleWake:)
                                                               name:NSWorkspaceDidWakeNotification
                                                             object:nil];
    
    // Create menu bar item
    self.statusItem = [[NSStatusBar systemStatusBar] statusItemWithLength:NSVariableStatusItemLength];
    
    // Set icon from app bundle (template image: transparent bg, macOS auto-tints)
    NSString *iconPath = [[NSBundle mainBundle] pathForResource:@"MenuIcon" ofType:@"png"];
    NSImage *icon = iconPath ? [[NSImage alloc] initWithContentsOfFile:iconPath] : nil;
    if (!icon) {
        // Fallback: create a simple flame text icon
        self.statusItem.button.title = @"⚡";
    } else {
        icon.size = NSMakeSize(18, 18);
        [icon setTemplate:YES];
        self.statusItem.button.image = icon;
    }
    
    // Build menu
    [self rebuildMenu:NO];
    
    // Start the server
    [self startServer];
    
    // Health check every 5 seconds
    self.healthTimer = [NSTimer scheduledTimerWithTimeInterval:5.0
                                                       repeats:YES
                                                         block:^(NSTimer *t) {
                                                             [self checkHealth];
                                                         }];
    
    // Auto-check for updates on launch
    [self fetchLatestVersion];
    
    // Enable as login item
    [self enableLoginItem];
}

- (void)rebuildMenu:(BOOL)running {
    NSMenu *menu = [[NSMenu alloc] init];
    
    NSMenuItem *statusItem = [[NSMenuItem alloc] initWithTitle:running ? @"● Running" : @"○ Stopped"
                                                       action:nil
                                                keyEquivalent:@""];
    statusItem.enabled = NO;
    [menu addItem:statusItem];
    
    [menu addItem:[NSMenuItem separatorItem]];
    
    if (running) {
        [menu addItemWithTitle:@"Restart" action:@selector(restartServer) keyEquivalent:@"r"];
    } else {
        [menu addItemWithTitle:@"Start" action:@selector(startServer) keyEquivalent:@"s"];
    }
    
    [menu addItem:[NSMenuItem separatorItem]];
    [menu addItemWithTitle:@"Export Pairing File…" action:@selector(exportPairingFile) keyEquivalent:@"p"];
    [menu addItemWithTitle:@"Run Benchmark" action:@selector(openBenchmark) keyEquivalent:@"b"];
    
    NSString *currentVersion = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleShortVersionString"];
    if (!currentVersion) currentVersion = @"?";
    
    if (self.updateAvailable && self.latestVersion) {
        NSString *title = [NSString stringWithFormat:@"⬆ Update to v%@", self.latestVersion];
        [menu addItemWithTitle:title action:@selector(checkForUpdates) keyEquivalent:@"u"];
    } else {
        NSMenuItem *versionItem = [[NSMenuItem alloc] initWithTitle:[NSString stringWithFormat:@"v%@ (latest)", currentVersion]
                                                             action:nil
                                                      keyEquivalent:@""];
        versionItem.enabled = NO;
        [menu addItem:versionItem];
    }
    
    [menu addItemWithTitle:@"View Logs" action:@selector(viewLogs) keyEquivalent:@"l"];
    [menu addItem:[NSMenuItem separatorItem]];
    [menu addItemWithTitle:@"Quit Octane Accelerator" action:@selector(quitApp) keyEquivalent:@"q"];
    
    self.statusItem.menu = menu;
}

- (NSString *)serverBinaryPath {
    return [[NSBundle mainBundle] pathForResource:@"octane-accelerator" ofType:nil inDirectory:@""];
    // Falls back to looking next to the app
}

- (NSString *)findServerBinary {
    // Check inside app bundle
    NSString *bundlePath = [[NSBundle mainBundle].executablePath stringByDeletingLastPathComponent];
    NSString *serverPath = [bundlePath stringByAppendingPathComponent:@"octane-accelerator"];
    if ([[NSFileManager defaultManager] fileExistsAtPath:serverPath]) {
        return serverPath;
    }
    // Check ~/.octane/
    NSString *homePath = [NSHomeDirectory() stringByAppendingPathComponent:@".octane/octane-accelerator"];
    if ([[NSFileManager defaultManager] fileExistsAtPath:homePath]) {
        return homePath;
    }
    return nil;
}

- (void)startServer {
    NSString *binary = [self findServerBinary];
    if (!binary) {
        NSLog(@"Server binary not found");
        [self rebuildMenu:NO];
        return;
    }
    
    // Create log directory
    NSString *logDir = [NSHomeDirectory() stringByAppendingPathComponent:@".octane"];
    [[NSFileManager defaultManager] createDirectoryAtPath:logDir withIntermediateDirectories:YES attributes:nil error:nil];
    NSString *logPath = [logDir stringByAppendingPathComponent:@"accelerator.log"];
    
    // Fork and exec the server
    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    
    // Redirect stdout+stderr to log file (truncate on each start for clean logs)
    int logFd = open([logPath fileSystemRepresentation], O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (logFd >= 0) {
        posix_spawn_file_actions_adddup2(&actions, logFd, STDOUT_FILENO);
        posix_spawn_file_actions_adddup2(&actions, logFd, STDERR_FILENO);
    }
    
    const char *argv[] = {[binary fileSystemRepresentation], NULL};
    const char *envp[] = {NULL};
    
    pid_t pid;
    int ret = posix_spawn(&pid, [binary fileSystemRepresentation], &actions, NULL, (char *const *)argv, (char *const *)envp);
    posix_spawn_file_actions_destroy(&actions);
    if (logFd >= 0) close(logFd);
    
    if (ret == 0) {
        self.serverPID = pid;
        NSLog(@"Server started with PID %d", pid);
        [self rebuildMenu:YES];
    } else {
        NSLog(@"Failed to start server: %d", ret);
        [self rebuildMenu:NO];
    }
}

- (void)stopServer {
    if (self.serverPID > 0) {
        kill(self.serverPID, SIGTERM);
        int status;
        waitpid(self.serverPID, &status, WNOHANG);
        self.serverPID = 0;
    }
    [self rebuildMenu:NO];
}

- (void)restartServer {
    [self stopServer];
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        [self startServer];
    });
}

- (void)checkHealth {
    // Quick non-blocking check
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSURL *url = [NSURL URLWithString:@"http://127.0.0.1:19876/health"];
        NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:url];
        req.timeoutInterval = 2.0;
        
        NSURLSessionDataTask *task = [[NSURLSession sharedSession] dataTaskWithRequest:req
            completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
                BOOL running = NO;
                if (!error && [(NSHTTPURLResponse *)response statusCode] == 200) {
                    running = YES;
                }
                dispatch_async(dispatch_get_main_queue(), ^{
                    [self rebuildMenu:running];
                    // If server died, try restarting
                    if (!running && self.serverPID > 0) {
                        int status;
                        pid_t result = waitpid(self.serverPID, &status, WNOHANG);
                        if (result != 0) {
                            self.serverPID = 0;
                            [self startServer];
                        }
                    }
                });
            }];
        [task resume];
    });
}

- (void)viewLogs {
    NSString *logPath = [NSHomeDirectory() stringByAppendingPathComponent:@".octane/accelerator.log"];
    [[NSWorkspace sharedWorkspace] openURL:[NSURL fileURLWithPath:logPath]];
}

- (void)checkForUpdates {
    // Just refresh the latest version and update the menu indicator
    [self fetchLatestVersion];
}

- (void)fetchLatestVersion {
    NSString *currentVersion = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleShortVersionString"];
    if (!currentVersion) currentVersion = @"0.0.0";
    
    NSURL *url = [NSURL URLWithString:@"https://api.github.com/repos/octane-fast/octane-accelerator/releases/latest"];
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:url];
    [req setValue:@"application/vnd.github+json" forHTTPHeaderField:@"Accept"];
    req.timeoutInterval = 10.0;
    
    NSURLSessionDataTask *task = [[NSURLSession sharedSession] dataTaskWithRequest:req
        completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
            dispatch_async(dispatch_get_main_queue(), ^{
                if (error || [(NSHTTPURLResponse *)response statusCode] != 200) {
                    // Silent fail on auto-check; show alert only on manual check
                    return;
                }
                
                NSDictionary *release = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
                NSString *tagName = release[@"tag_name"];
                if (!tagName) return;
                
                NSString *latestVersion = [tagName stringByReplacingOccurrencesOfString:@"v" withString:@""];
                self.latestVersion = latestVersion;
                
                if ([latestVersion compare:currentVersion options:NSNumericSearch] == NSOrderedDescending) {
                    self.updateAvailable = YES;
                    [self rebuildMenu:self.serverPID > 0];
                } else {
                    self.updateAvailable = NO;
                    [self rebuildMenu:self.serverPID > 0];
                }
            });
        }];
    [task resume];
}

- (void)promptInstallUpdate {
    // Find the macOS DMG asset
    NSURL *url = [NSURL URLWithString:@"https://api.github.com/repos/octane-fast/octane-accelerator/releases/latest"];
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:url];
    [req setValue:@"application/vnd.github+json" forHTTPHeaderField:@"Accept"];
    req.timeoutInterval = 10.0;
    
    NSURLSessionDataTask *task = [[NSURLSession sharedSession] dataTaskWithRequest:req
        completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
            dispatch_async(dispatch_get_main_queue(), ^{
                if (error || [(NSHTTPURLResponse *)response statusCode] != 200) return;
                
                NSDictionary *release = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
                NSString *dmgURL = nil;
                for (NSDictionary *asset in release[@"assets"]) {
                    NSString *name = asset[@"name"];
                    if ([name hasSuffix:@".dmg"] && [name containsString:@"macos"]) {
                        dmgURL = asset[@"browser_download_url"];
                        break;
                    }
                }
                
                if (!dmgURL) {
                    [[NSWorkspace sharedWorkspace] openURL:[NSURL URLWithString:@"https://github.com/octane-fast/octane-accelerator/releases/latest"]];
                    return;
                }
                
                NSString *currentVersion = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleShortVersionString"];
                NSAlert *alert = [[NSAlert alloc] init];
                alert.messageText = [NSString stringWithFormat:@"Update Available: v%@", self.latestVersion];
                alert.informativeText = [NSString stringWithFormat:@"You have v%@. Download and install v%@?", currentVersion, self.latestVersion];
                [alert addButtonWithTitle:@"Download & Install"];
                [alert addButtonWithTitle:@"Later"];
                if ([alert runModal] == NSAlertFirstButtonReturn) {
                    [self downloadAndInstallDMG:dmgURL version:self.latestVersion];
                }
            });
        }];
    [task resume];
}

- (void)downloadAndInstallDMG:(NSString *)urlStr version:(NSString *)version {
    NSURL *url = [NSURL URLWithString:urlStr];
    NSString *tmpDir = [NSTemporaryDirectory() stringByAppendingPathComponent:@"octane-update"];
    [[NSFileManager defaultManager] createDirectoryAtPath:tmpDir withIntermediateDirectories:YES attributes:nil error:nil];
    NSString *dmgPath = [tmpDir stringByAppendingPathComponent:[NSString stringWithFormat:@"octane-accelerator-%@.dmg", version]];
    
    NSAlert *progress = [[NSAlert alloc] init];
    progress.messageText = @"Downloading Update";
    progress.informativeText = @"Downloading v%@\u2026 This may take a moment.";
    progress.alertStyle = NSAlertStyleInformational;
    
    // Show a progress alert (non-blocking)
    NSURLSessionDownloadTask *downloadTask = [[NSURLSession sharedSession] downloadTaskWithURL:url
        completionHandler:^(NSURL *location, NSURLResponse *response, NSError *error) {
            dispatch_async(dispatch_get_main_queue(), ^{
                if (error) {
                    NSAlert *alert = [[NSAlert alloc] init];
                    alert.messageText = @"Download Failed";
                    alert.informativeText = error.localizedDescription;
                    alert.alertStyle = NSAlertStyleWarning;
                    [alert runModal];
                    return;
                }
                
                // Move downloaded file
                [[NSFileManager defaultManager] removeItemAtPath:dmgPath error:nil];
                [[NSFileManager defaultManager] moveItemAtPath:location.path toPath:dmgPath error:nil];
                
                // Mount the DMG
                NSTask *mount = [[NSTask alloc] init];
                mount.launchPath = @"/usr/bin/hdiutil";
                mount.arguments = @[@"attach", dmgPath, @"-nobrowse", @"-quiet"];
                [mount launch];
                [mount waitUntilExit];
                
                if (mount.terminationStatus != 0) {
                    NSAlert *alert = [[NSAlert alloc] init];
                    alert.messageText = @"Install Failed";
                    alert.informativeText = @"Could not mount the downloaded DMG.";
                    [alert runModal];
                    return;
                }
                
                // Find the mounted volume
                NSString *volumePath = nil;
                for (NSString *vol in [[NSFileManager defaultManager] contentsOfDirectoryAtPath:@"/Volumes" error:nil]) {
                    if ([vol containsString:@"Octane"]) {
                        volumePath = [@"/Volumes" stringByAppendingPathComponent:vol];
                        break;
                    }
                }
                
                if (!volumePath) {
                    NSAlert *alert = [[NSAlert alloc] init];
                    alert.messageText = @"Install Failed";
                    alert.informativeText = @"Could not find mounted volume.";
                    [alert runModal];
                    return;
                }
                
                // Copy .app to /Applications
                NSString *srcApp = [volumePath stringByAppendingPathComponent:@"Octane Accelerator.app"];
                NSString *dstApp = @"/Applications/Octane Accelerator.app";
                
                // Remove old app
                [[NSFileManager defaultManager] removeItemAtPath:dstApp error:nil];
                
                NSError *copyError = nil;
                [[NSFileManager defaultManager] copyItemAtPath:srcApp toPath:dstApp error:&copyError];
                
                // Unmount DMG
                NSTask *unmount = [[NSTask alloc] init];
                unmount.launchPath = @"/usr/bin/hdiutil";
                unmount.arguments = @[@"detach", volumePath, @"-force"];
                [unmount launch];
                [unmount waitUntilExit];
                
                // Clean up
                [[NSFileManager defaultManager] removeItemAtPath:tmpDir error:nil];
                
                if (copyError) {
                    NSAlert *alert = [[NSAlert alloc] init];
                    alert.messageText = @"Install Failed";
                    alert.informativeText = copyError.localizedDescription;
                    [alert runModal];
                    return;
                }
                
                // Relaunch
                NSAlert *done = [[NSAlert alloc] init];
                done.messageText = [NSString stringWithFormat:@"Updated to v%@", version];
                done.informativeText = @"The app will relaunch now.";
                done.alertStyle = NSAlertStyleInformational;
                [done runModal];
                
                // Relaunch the app
                NSTask *relaunch = [[NSTask alloc] init];
                relaunch.launchPath = @"/usr/bin/open";
                relaunch.arguments = @[dstApp];
                [relaunch launch];
                
                [NSApp terminate:nil];
            });
        }];
    [downloadTask resume];
}

- (void)exportPairingFile {
    NSSavePanel *panel = [NSSavePanel savePanel];
    panel.title = @"Export Pairing File";
    panel.nameFieldStringValue = @"octane-prover.pair";
    panel.allowedContentTypes = @[[UTType typeWithFilenameExtension:@"pair"]];
    panel.message = @"Save this file and import it into your remote Octane wallet to connect.";
    
    [panel beginWithCompletionHandler:^(NSModalResponse result) {
        if (result != NSModalResponseOK || !panel.URL) return;
        
        NSString *path = panel.URL.path;
        
        // Call the server's pairing generator via HTTP
        NSURL *url = [NSURL URLWithString:@"http://127.0.0.1:19876/pair/export"];
        NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:url];
        req.HTTPMethod = @"POST";
        req.timeoutInterval = 5.0;
        
        NSURLSessionDataTask *task = [[NSURLSession sharedSession] dataTaskWithRequest:req
            completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
                if (error || [(NSHTTPURLResponse *)response statusCode] != 200) {
                    dispatch_async(dispatch_get_main_queue(), ^{
                        NSAlert *alert = [[NSAlert alloc] init];
                        alert.messageText = @"Export Failed";
                        alert.informativeText = error ? error.localizedDescription : @"Server returned an error";
                        [alert runModal];
                    });
                    return;
                }
                
                // Write the pairing data to the chosen file
                [data writeToFile:path atomically:YES];
                
                dispatch_async(dispatch_get_main_queue(), ^{
                    NSAlert *alert = [[NSAlert alloc] init];
                    alert.messageText = @"Pairing File Exported";
                    alert.informativeText = @"Transfer this file to your remote device and import it into the Octane wallet. Do not share it — it grants access to this prover.";
                    alert.alertStyle = NSAlertStyleInformational;
                    [alert runModal];
                });
            }];
        [task resume];
    }];
}

- (void)handleWake:(NSNotification *)notification {
    // On system wake, immediately check health and restart server if needed
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        [self checkHealth];
    });
}

- (void)openBenchmark {
    if (self.benchWindow && [self.benchWindow isVisible]) {
        [self.benchWindow makeKeyAndOrderFront:nil];
        [NSApp activateIgnoringOtherApps:YES];
        return;
    }
    
    NSRect frame = NSMakeRect(0, 0, 400, 320);
    self.benchWindow = [[NSWindow alloc] initWithContentRect:frame
                                                   styleMask:NSWindowStyleMaskTitled | NSWindowStyleMaskClosable
                                                     backing:NSBackingStoreBuffered
                                                       defer:NO];
    self.benchWindow.title = @"Octane Accelerator \u2014 Benchmark";
    [self.benchWindow center];
    
    NSView *content = self.benchWindow.contentView;
    content.wantsLayer = YES;
    content.layer.backgroundColor = [NSColor colorWithRed:0.05 green:0.05 blue:0.07 alpha:1.0].CGColor;
    
    // Title label
    NSTextField *titleLabel = [NSTextField labelWithString:@"Range Proof Benchmark"];
    titleLabel.font = [NSFont boldSystemFontOfSize:18];
    titleLabel.textColor = [NSColor whiteColor];
    titleLabel.frame = NSMakeRect(20, 260, 360, 30);
    [content addSubview:titleLabel];
    
    NSTextField *descLabel = [NSTextField wrappingLabelWithString:@"Generates a PVAC range proof using the native accelerator and measures the time."];
    descLabel.font = [NSFont systemFontOfSize:12];
    descLabel.textColor = [NSColor colorWithWhite:0.6 alpha:1.0];
    descLabel.frame = NSMakeRect(20, 220, 360, 35);
    [content addSubview:descLabel];
    
    // Progress bar (determinate — shows real proof progress)
    NSProgressIndicator *progress = [[NSProgressIndicator alloc] initWithFrame:NSMakeRect(20, 195, 360, 6)];
    progress.style = NSProgressIndicatorStyleBar;
    progress.indeterminate = NO;
    progress.minValue = 0;
    progress.maxValue = 1.0;
    progress.doubleValue = 0;
    progress.hidden = YES;
    progress.identifier = @"progressBar";
    [content addSubview:progress];
    
    // Result label
    NSTextField *resultLabel = [NSTextField labelWithString:@""];
    resultLabel.font = [NSFont monospacedSystemFontOfSize:14 weight:NSFontWeightMedium];
    resultLabel.textColor = [NSColor colorWithRed:0.39 green:0.40 blue:0.95 alpha:1.0];
    resultLabel.frame = NSMakeRect(20, 110, 360, 80);
    resultLabel.maximumNumberOfLines = 4;
    resultLabel.tag = 100;
    [content addSubview:resultLabel];
    
    // Run button
    NSButton *runBtn = [NSButton buttonWithTitle:@"Run Range Proof" target:self action:@selector(runBenchmark:)];
    runBtn.bezelStyle = NSBezelStyleRounded;
    runBtn.frame = NSMakeRect(120, 50, 160, 40);
    runBtn.tag = 101;
    [content addSubview:runBtn];
    
    [self.benchWindow makeKeyAndOrderFront:nil];
    [NSApp activateIgnoringOtherApps:YES];
}

- (void)runBenchmark:(NSButton *)sender {
    NSView *content = self.benchWindow.contentView;
    NSTextField *resultLabel = [content viewWithTag:100];
    NSButton *runBtn = [content viewWithTag:101];
    NSProgressIndicator *progress = nil;
    for (NSView *v in content.subviews) {
        if ([v.identifier isEqualToString:@"progressBar"]) { progress = (NSProgressIndicator *)v; break; }
    }
    
    resultLabel.stringValue = @"Starting benchmark\u2026";
    resultLabel.textColor = [NSColor colorWithWhite:0.5 alpha:1.0];
    runBtn.enabled = NO;
    progress.hidden = NO;
    progress.doubleValue = 0;
    
    self.benchBuffer = [NSMutableData data];
    
    NSURL *url = [NSURL URLWithString:@"http://127.0.0.1:19876/benchmark"];
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:url];
    req.HTTPMethod = @"POST";
    req.timeoutInterval = 300.0;
    [req setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
    req.HTTPBody = [@"{\"count\":3}" dataUsingEncoding:NSUTF8StringEncoding];
    
    NSURLSession *session = [NSURLSession sessionWithConfiguration:[NSURLSessionConfiguration defaultSessionConfiguration]
                                                          delegate:self
                                                     delegateQueue:[NSOperationQueue mainQueue]];
    NSURLSessionDataTask *task = [session dataTaskWithRequest:req];
    [task resume];
}

- (void)URLSession:(NSURLSession *)session dataTask:(NSURLSessionDataTask *)dataTask didReceiveData:(NSData *)data {
    [self.benchBuffer appendData:data];
    
    // Parse newline-delimited JSON lines from buffer
    NSString *str = [[NSString alloc] initWithData:self.benchBuffer encoding:NSUTF8StringEncoding];
    if (!str) return;
    
    NSArray *lines = [str componentsSeparatedByString:@"\n"];
    // Keep the last incomplete line in the buffer
    NSString *lastLine = [lines lastObject];
    self.benchBuffer = [[lastLine dataUsingEncoding:NSUTF8StringEncoding] mutableCopy] ?: [NSMutableData data];
    
    NSView *content = self.benchWindow.contentView;
    NSTextField *resultLabel = [content viewWithTag:100];
    NSProgressIndicator *progress = nil;
    for (NSView *v in content.subviews) {
        if ([v.identifier isEqualToString:@"progressBar"]) { progress = (NSProgressIndicator *)v; break; }
    }
    
    for (NSUInteger i = 0; i < lines.count - 1; i++) {
        NSString *line = lines[i];
        if (line.length == 0) continue;
        
        NSData *jsonData = [line dataUsingEncoding:NSUTF8StringEncoding];
        NSDictionary *obj = [NSJSONSerialization JSONObjectWithData:jsonData options:0 error:nil];
        if (!obj) continue;
        
        if (obj[@"done"]) {
            // Final result
            double avg_ms = [obj[@"avg_ms"] doubleValue];
            int count = [obj[@"count"] intValue];
            double total_ms = [obj[@"total_ms"] doubleValue];
            NSString *avgStr = avg_ms < 1000 ? [NSString stringWithFormat:@"%.0f ms", avg_ms]
                                             : [NSString stringWithFormat:@"%.2f s", avg_ms / 1000];
            NSString *totalStr = total_ms < 1000 ? [NSString stringWithFormat:@"%.0f ms", total_ms]
                                                 : [NSString stringWithFormat:@"%.1f s", total_ms / 1000];
            resultLabel.stringValue = [NSString stringWithFormat:@"\u2713 %d range proofs generated\n\nAverage: %@\nTotal: %@", count, avgStr, totalStr];
            resultLabel.textColor = [NSColor colorWithRed:0.39 green:0.40 blue:0.95 alpha:1.0];
            progress.doubleValue = 1.0;
        } else if (obj[@"step"]) {
            // Progress update
            int step = [obj[@"step"] intValue];
            int total = [obj[@"total"] intValue];
            if (total > 0) progress.doubleValue = (double)step / (double)total;
            NSString *msg = obj[@"msg"];
            if (msg) resultLabel.stringValue = msg;
        } else if (obj[@"error"]) {
            resultLabel.stringValue = [NSString stringWithFormat:@"Error: %@", obj[@"error"]];
            resultLabel.textColor = [NSColor redColor];
        }
    }
}

- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task didCompleteWithError:(NSError *)error {
    NSView *content = self.benchWindow.contentView;
    NSButton *runBtn = [content viewWithTag:101];
    NSTextField *resultLabel = [content viewWithTag:100];
    runBtn.enabled = YES;
    
    if (error) {
        resultLabel.stringValue = [NSString stringWithFormat:@"Error: %@", error.localizedDescription];
        resultLabel.textColor = [NSColor redColor];
    }
    [session invalidateAndCancel];
}

- (void)enableLoginItem {
    if (@available(macOS 13.0, *)) {
        SMAppService *service = [SMAppService mainAppService];
        if (service.status != SMAppServiceStatusEnabled) {
            NSError *error = nil;
            [service registerAndReturnError:&error];
            if (error) {
                NSLog(@"Failed to register login item: %@", error);
            }
        }
    }
}

- (void)quitApp {
    [self stopServer];
    [NSApp terminate:nil];
}

- (void)applicationWillTerminate:(NSNotification *)notification {
    [self stopServer];
}

@end

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        NSApplication *app = [NSApplication sharedApplication];
        [app setActivationPolicy:NSApplicationActivationPolicyAccessory]; // No dock icon
        
        AppDelegate *delegate = [[AppDelegate alloc] init];
        app.delegate = delegate;
        [app run];
    }
    return 0;
}
