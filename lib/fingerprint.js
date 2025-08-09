// === Enhanced Fingerprint Protection Module ===
// This module handles advanced browser fingerprint spoofing, user agent changes,
// and comprehensive bot detection evasion techniques.

 /**
  * Safe property definition helper for Puppeteer 24.x compatibility
  * Prevents "Cannot redefine property" errors
  */
 function safeDefineProperty(obj, prop, descriptor) {
   try {
     const existing = Object.getOwnPropertyDescriptor(obj, prop);
     if (existing && !existing.configurable) {
       return false; // Skip non-configurable properties
     }
     Object.defineProperty(obj, prop, {
       configurable: true,
       ...descriptor
     });
     return true;
   } catch (err) {
     return false; // Failed to define, continue silently
   }
 }

// Default values for fingerprint spoofing if not set to 'random'
const DEFAULT_PLATFORM = 'Win32';
const DEFAULT_TIMEZONE = 'America/New_York';

/**
 * Generates realistic screen resolutions based on common monitor sizes
 * @returns {object} Screen resolution object with width and height
 */
function getRealisticScreenResolution() {
  const commonResolutions = [
    { width: 1920, height: 1080 }, // Full HD - most common
    { width: 1366, height: 768 },  // Common laptop
    { width: 1440, height: 900 },  // MacBook Air
    { width: 1536, height: 864 },  // Scaled HD
    { width: 1600, height: 900 },  // 16:9 widescreen
    { width: 2560, height: 1440 }, // 1440p
    { width: 1280, height: 720 },  // 720p
    { width: 3440, height: 1440 }  // Ultrawide
  ];
  
  return commonResolutions[Math.floor(Math.random() * commonResolutions.length)];
}

/**
 * Generates an object with randomized but realistic browser fingerprint values.
 * This is used to spoof various navigator and screen properties to make
 * the headless browser instance appear more like a regular user's browser
 * and bypass fingerprint-based bot detection.
 *
 * @returns {object} An object containing the spoofed fingerprint properties
 */
function getRandomFingerprint() {
  const resolution = getRealisticScreenResolution();
  
  return {
    deviceMemory: [4, 8, 16, 32][Math.floor(Math.random() * 4)],
    hardwareConcurrency: [2, 4, 6, 8, 12, 16][Math.floor(Math.random() * 6)],
    screen: {
      width: resolution.width,
      height: resolution.height,
      availWidth: resolution.width,
      availHeight: resolution.height - 40, // Account for taskbar
      colorDepth: 24,
      pixelDepth: 24
    },
    platform: Math.random() > 0.3 ? 'Win32' : 'MacIntel',
    timezone: ['America/New_York', 'America/Los_Angeles', 'Europe/London', 'America/Chicago'][Math.floor(Math.random() * 4)],
    language: ['en-US', 'en-GB', 'en-CA'][Math.floor(Math.random() * 3)],
    cookieEnabled: true,
    doNotTrack: Math.random() > 0.7 ? '1' : null
  };
}

/**
 * Enhanced user agent spoofing with latest browser versions and comprehensive stealth protection
 * @param {import('puppeteer').Page} page - The Puppeteer page instance
 * @param {object} siteConfig - The site configuration object
 * @param {boolean} forceDebug - Whether debug logging is enabled
 * @param {string} currentUrl - The current URL being processed (for logging)
 * @returns {Promise<void>}
 */
async function applyUserAgentSpoofing(page, siteConfig, forceDebug, currentUrl) {
  if (!siteConfig.userAgent) return;

  if (forceDebug) console.log(`[debug] Enhanced userAgent spoofing enabled for ${currentUrl}: ${siteConfig.userAgent}`);
  
  // Updated user agents with latest browser versions
  const userAgents = {
    chrome: [
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
      "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
    ],
    firefox: [
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) Gecko/20100101 Firefox/133.0",
      "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0"
    ],
    safari: [
      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15",
      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15"
    ]
  };
  
  const selectedUserAgents = userAgents[siteConfig.userAgent.toLowerCase()];
  const ua = selectedUserAgents ? selectedUserAgents[Math.floor(Math.random() * selectedUserAgents.length)] : null;
  
  if (ua) {
    await page.setUserAgent(ua);
    
    // Apply comprehensive stealth protection when userAgent is set
    if (forceDebug) console.log(`[debug] Applying enhanced stealth protection for ${currentUrl}`);
    
    try {
      await page.evaluateOnNewDocument((userAgent) => {
       // Prevent duplicate execution in Puppeteer 24.x
       if (window.__stealthProtectionApplied) {
         return;
       }
       window.__stealthProtectionApplied = true;

      // IMMEDIATE protection against property redefinition errors
      // Override Object.defineProperty FIRST before any other code runs
      const originalDefineProperty = Object.defineProperty;
      Object.defineProperty = function(obj, prop, descriptor) {
        // Problematic properties that cause errors in Puppeteer 24.x
        const problematicProps = [
          'href', 'origin', 'protocol', 'host', 'hostname', 'port', 'pathname', 
          'search', 'hash', 'ancestorOrigins', 'assign', 'replace', 'reload'
        ];
        
        // Skip problematic properties entirely
        if (problematicProps.includes(prop)) {
          return obj; // Return object unchanged
        }
        
        // Skip location-related objects
        if (obj === window.location || obj === document.location || 
            obj === Location.prototype || obj === HTMLAnchorElement.prototype ||
            (obj && obj.constructor && obj.constructor.name === 'Location')) {
          return obj; // Return object unchanged
        }
        
        // Try original defineProperty with error handling
        try {
          const existing = Object.getOwnPropertyDescriptor(obj, prop);
          if (existing && !existing.configurable) {
            return obj; // Skip non-configurable properties
          }
          return originalDefineProperty.call(this, obj, prop, {
            configurable: true,
            ...descriptor
          });
        } catch (e) {
          return obj; // Fail silently instead of throwing
        }
      };
      
       
       // Safe property definition helper
       const safeDefine = (obj, prop, descriptor) => {
         try {
           // Skip problematic properties that are non-configurable in Puppeteer 24.x
           const problematicProps = [
             'href', 'origin', 'protocol', 'host', 'hostname', 'port', 'pathname', 
             'search', 'hash', 'ancestorOrigins', 'assign', 'replace', 'reload'
           ];
           
           if (problematicProps.includes(prop)) {
             return false; // Skip these properties to avoid "Cannot redefine property" errors
           }

          // Additional check for location-related objects in iframe contexts
          if (obj === window.location || obj === document.location || 
              obj === Location.prototype || obj === HTMLAnchorElement.prototype ||
              (obj && obj.constructor && obj.constructor.name === 'Location')) {
            return false; // Skip all location object property modifications
          }

           const existing = Object.getOwnPropertyDescriptor(obj, prop);
           if (existing && !existing.configurable) {
             return false;
           }
           return originalDefineProperty.call(Object, obj, prop, { configurable: true, ...descriptor });
           return true;
         } catch (e) {
           return false;
         }
       };
       
       // Safe property deletion helper
       const safeDelete = (obj, prop) => {
         try {
        // Skip problematic properties
        const problematicProps = [
          'href', 'origin', 'protocol', 'host', 'hostname', 'port', 'pathname', 
          'search', 'hash', 'ancestorOrigins', 'assign', 'replace', 'reload'
        ];
        
        if (problematicProps.includes(prop)) {
          return false;
        }
        
          // Additional check for location-related objects in iframe contexts
          if (obj === window.location || obj === document.location || 
              obj === Location.prototype || obj === HTMLAnchorElement.prototype ||
              (obj && obj.constructor && obj.constructor.name === 'Location')) {
            return false; // Skip all location object property modifications
          }

           delete obj[prop];
           safeDefine(obj, prop, {
             get: () => undefined,
             enumerable: false
           });
         } catch (e) {
           // Ignore errors for properties that can't be deleted
         }
       };
        // 1. Enhanced webdriver removal with descriptor manipulation
       safeDelete(navigator, 'webdriver');
        
        // 2. Enhanced automation detection removal
        const automationProps = [
          'callPhantom', '_phantom', '__nightmare', '_selenium',
          '__selenium_unwrapped', '__webdriver_evaluate', '__driver_evaluate',
          '__webdriver_script_function', '__webdriver_script_func',
          '__webdriver_script_fn', '__fxdriver_evaluate', '__driver_unwrapped',
          '__webdriver_unwrapped', '__selenium_evaluate', '__fxdriver_unwrapped',
          'spawn', 'emit', 'Buffer', '__webdriver_script_func', 'domAutomation',
          'domAutomationController', '__lastWatirAlert', '__lastWatirConfirm',
          '__lastWatirPrompt', '_Selenium_IDE_Recorder', '_selenium', 'calledSelenium',
          '__webdriver_script_function', '__webdriver_script_func'
        ];
        
        automationProps.forEach(prop => {
         safeDelete(window, prop);
         safeDelete(navigator, prop);
        });
        
        // 3. Enhanced Chrome runtime simulation
        if (!window.chrome || !window.chrome.runtime) {
         safeDefine(window, 'chrome', {
           get: () => ({
            runtime: {
              onConnect: { addListener: () => {}, removeListener: () => {} },
              onMessage: { addListener: () => {}, removeListener: () => {} },
              sendMessage: () => {},
              connect: () => ({
                onMessage: { addListener: () => {}, removeListener: () => {} },
                postMessage: () => {},
                disconnect: () => {}
              }),
              getManifest: () => ({
                name: "Chrome",
                version: "131.0.0.0"
              }),
              getURL: (path) => `chrome-extension://invalid/${path}`,
              id: undefined
            },
            loadTimes: () => ({
              commitLoadTime: performance.now() - Math.random() * 1000,
              connectionInfo: 'http/1.1',
              finishDocumentLoadTime: performance.now() - Math.random() * 500,
              finishLoadTime: performance.now() - Math.random() * 100,
              firstPaintAfterLoadTime: performance.now() - Math.random() * 50,
              firstPaintTime: performance.now() - Math.random() * 200,
              navigationType: 'Navigation',
              npnNegotiatedProtocol: 'unknown',
              requestTime: performance.now() - Math.random() * 2000,
              startLoadTime: performance.now() - Math.random() * 1500,
              wasAlternateProtocolAvailable: false,
              wasFetchedViaSpdy: false,
              wasNpnNegotiated: false
            }),
            csi: () => ({
              onloadT: Date.now(),
              pageT: Math.random() * 1000,
              startE: Date.now() - Math.random() * 2000,
              tran: Math.floor(Math.random() * 20)
            }),
            app: {
              isInstalled: false,
              InstallState: { DISABLED: 'disabled', INSTALLED: 'installed', NOT_INSTALLED: 'not_installed' },
              RunningState: { CANNOT_RUN: 'cannot_run', READY_TO_RUN: 'ready_to_run', RUNNING: 'running' }
            }
           }),
           enumerable: true
         });
        }
        
        // 4. Realistic plugins based on user agent
        const isChrome = userAgent.includes('Chrome');
        const isFirefox = userAgent.includes('Firefox');
        const isSafari = userAgent.includes('Safari') && !userAgent.includes('Chrome');
        
        let plugins = [];
        if (isChrome) {
          plugins = [
            { name: 'Chrome PDF Plugin', length: 1, description: 'Portable Document Format', filename: 'internal-pdf-viewer' },
            { name: 'Chrome PDF Viewer', length: 1, description: 'PDF Viewer', filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai' },
            { name: 'Native Client', length: 2, description: 'Native Client Executable', filename: 'internal-nacl-plugin' }
          ];
        } else if (isFirefox) {
          plugins = [
            { name: 'PDF.js', length: 2, description: 'Portable Document Format', filename: 'internal-pdf-js' }
          ];
        } else if (isSafari) {
          plugins = [
            { name: 'WebKit built-in PDF', length: 1, description: 'Portable Document Format', filename: 'internal-pdf-viewer' }
          ];
        }
        
       safeDefine(navigator, 'plugins', {
         get: () => plugins,
         enumerable: true
       });
        
        // 5. Enhanced language spoofing
        const languages = ['en-US', 'en'];
       safeDefine(navigator, 'languages', {
         get: () => languages,
         enumerable: true
       });
       safeDefine(navigator, 'language', {
         get: () => languages[0],
         enumerable: true
       });
        
        // 6. Vendor and product info based on user agent
        let vendor = 'Google Inc.';
        let product = 'Gecko';
        
        if (isFirefox) {
          vendor = '';
          product = 'Gecko';
        } else if (isSafari) {
          vendor = 'Apple Computer, Inc.';
          product = 'Gecko';
        }
        
       safeDefine(navigator, 'vendor', {
         get: () => vendor,
         enumerable: true
       });
       safeDefine(navigator, 'product', {
         get: () => product,
         enumerable: true
       });
        
        // 7. Add realistic mimeTypes
       safeDefine(navigator, 'mimeTypes', {
          get: () => {
            if (isChrome) {
              return [
                { type: 'application/pdf', description: 'Portable Document Format', suffixes: 'pdf', enabledPlugin: plugins[0] },
                { type: 'application/x-google-chrome-pdf', description: 'Portable Document Format', suffixes: 'pdf', enabledPlugin: plugins[1] },
                { type: 'application/x-nacl', description: 'Native Client Executable', suffixes: '', enabledPlugin: plugins[2] }
              ];
            }
            return [];
          },
         enumerable: true
        });
        
        // 8. Enhanced permission API spoofing
        if (navigator.permissions && navigator.permissions.query) {
          const originalQuery = navigator.permissions.query;
         safeDefine(navigator.permissions, 'query', {
           value: function(parameters) {
            const granted = ['camera', 'microphone', 'notifications'];
            const denied = ['midi', 'push', 'speaker'];
            const prompt = ['geolocation'];
            
            if (granted.includes(parameters.name)) {
              return Promise.resolve({ state: 'granted', onchange: null });
            } else if (denied.includes(parameters.name)) {
              return Promise.resolve({ state: 'denied', onchange: null });
            } else if (prompt.includes(parameters.name)) {
              return Promise.resolve({ state: 'prompt', onchange: null });
            }
            return originalQuery.apply(this, arguments);
           },
           writable: true
         });
        }
        
        // 9. Spoof iframe contentWindow access (common detection method)
        const originalContentWindow = Object.getOwnPropertyDescriptor(HTMLIFrameElement.prototype, 'contentWindow');
        if (originalContentWindow) {
          safeDefine(HTMLIFrameElement.prototype, 'contentWindow', {
            get: function() {
              const win = originalContentWindow.get.call(this);
              if (win) {
                // Remove automation properties from iframe windows too
                automationProps.forEach(prop => {
                  try { 
                   safeDelete(win, prop);
                  } catch(e) {}
                });
              }
              return win;
            },
           enumerable: true
          });
        }
        
        // 10. Enhanced connection information spoofing
        if (navigator.connection) {
         safeDefine(navigator.connection, 'rtt', { get: () => Math.floor(Math.random() * 100) + 50 });
         safeDefine(navigator.connection, 'downlink', { get: () => Math.random() * 10 + 1 });
         safeDefine(navigator.connection, 'effectiveType', { get: () => '4g' });
         safeDefine(navigator.connection, 'saveData', { get: () => false });
        }
        
        // 11. Spoof WebGL fingerprinting
       if (window.WebGLRenderingContext) {
         const getParameter = WebGLRenderingContext.prototype.getParameter;
         safeDefine(WebGLRenderingContext.prototype, 'getParameter', {
           value: function(parameter) {
          if (parameter === 37445) { // UNMASKED_VENDOR_WEBGL
            return 'Intel Inc.';
          }
          if (parameter === 37446) { // UNMASKED_RENDERER_WEBGL
            return 'Intel Iris OpenGL Engine';
          }
          return getParameter.call(this, parameter);
           },
           writable: true
         });
       }
        
        // 12. Spoof canvas fingerprinting with subtle noise
        const originalToDataURL = HTMLCanvasElement.prototype.toDataURL;
       safeDefine(HTMLCanvasElement.prototype, 'toDataURL', {
         value: function(...args) {
          const context = this.getContext('2d');
          if (context) {
            // Add subtle noise to canvas to prevent fingerprinting
            const imageData = context.getImageData(0, 0, this.width, this.height);
            for (let i = 0; i < imageData.data.length; i += 4) {
              imageData.data[i] = imageData.data[i] + Math.floor(Math.random() * 3) - 1;
            }
            context.putImageData(imageData, 0, 0);
          }
          return originalToDataURL.apply(this, args);
         },
         writable: true
       });
        
        // 13. Enhanced Error.captureStackTrace to prevent detection
        if (Error.captureStackTrace) {
          const originalCaptureStackTrace = Error.captureStackTrace;
         safeDefine(Error, 'captureStackTrace', {
           value: function(targetObject, constructorOpt) {
            const result = originalCaptureStackTrace.call(this, targetObject, constructorOpt);
            if (targetObject.stack) {
              // Remove puppeteer-related stack traces
              targetObject.stack = targetObject.stack
                .split('\n')
                .filter(line => !line.includes('puppeteer') && !line.includes('DevTools') && !line.includes('chrome-devtools'))
                .join('\n');
            }
            return result;
           },
           writable: true
         });
        }
        
        // 14. Patch toString methods to prevent detection
       const originalToString = Function.prototype.toString;
       safeDefine(Function.prototype, 'toString', {
         value: new Proxy(originalToString, {
          apply: function(target, thisArg, argumentsList) {
            const result = target.apply(thisArg, argumentsList);
            return result.replace(/puppeteer/gi, 'browser').replace(/headless/gi, 'chrome');
          }
         }),
         writable: true
       });
        
        // 15. Spoof battery API if available
        if (navigator.getBattery) {
          const originalGetBattery = navigator.getBattery;
         safeDefine(navigator, 'getBattery', {
           value: function() {
            return Promise.resolve({
              charging: Math.random() > 0.5,
              chargingTime: Math.random() > 0.5 ? Infinity : Math.random() * 3600,
              dischargingTime: Math.random() * 7200,
              level: Math.random() * 0.99 + 0.01,
              addEventListener: () => {},
              removeEventListener: () => {},
              dispatchEvent: () => true
            });
           },
           writable: true
         });
        }
        
        // 16. Add realistic timing to console methods
        ['debug', 'error', 'info', 'log', 'warn'].forEach(method => {
          const original = console[method];
         safeDefine(console, method, {
           value: function(...args) {
            // Add tiny random delay to mimic human-like console timing
            setTimeout(() => original.apply(console, args), Math.random() * 5);
           },
           writable: true
         });
        });
        
      }, ua);
    } catch (stealthErr) {
     if (stealthErr.message.includes('Cannot redefine property')) {
       if (forceDebug) console.log(`[debug] Stealth protection skipped (already applied): ${currentUrl}`);
     } else {
      console.warn(`[enhanced stealth protection failed] ${currentUrl}: ${stealthErr.message}`);
      }
    }
  }
}

/**
 * Enhanced Brave browser spoofing with more realistic implementation
 * @param {import('puppeteer').Page} page - The Puppeteer page instance
 * @param {object} siteConfig - The site configuration object
 * @param {boolean} forceDebug - Whether debug logging is enabled
 * @param {string} currentUrl - The current URL being processed (for logging)
 * @returns {Promise<void>}
 */
async function applyBraveSpoofing(page, siteConfig, forceDebug, currentUrl) {
  if (!siteConfig.isBrave) return;

  if (forceDebug) console.log(`[debug] Enhanced Brave spoofing enabled for ${currentUrl}`);

try { 
  await page.evaluateOnNewDocument(() => {
     // Prevent duplicate execution
     if (window.__braveProtectionApplied) {
       return;
     }
     window.__braveProtectionApplied = true;
     
     const safeDefine = (obj, prop, descriptor) => {
       try {
         const existing = Object.getOwnPropertyDescriptor(obj, prop);
         if (existing && !existing.configurable) {
           return false;
         }
         Object.defineProperty(obj, prop, { configurable: true, ...descriptor });
         return true;
       } catch (e) {
         return false;
       }
     };
    // More comprehensive Brave spoofing
     safeDefine(navigator, 'brave', {
      get: () => ({
        isBrave: () => Promise.resolve(true),
        setBadge: () => {},
        clearBadge: () => {},
        getAdBlockEnabled: () => Promise.resolve(true),
        getShieldsEnabled: () => Promise.resolve(true)
      }),
       enumerable: true
    });
    
    // Brave-specific user agent adjustments
    if (navigator.userAgent && !navigator.userAgent.includes('Brave')) {
       safeDefine(navigator, 'userAgent', {
        get: () => navigator.userAgent.replace('Chrome/', 'Brave/').replace('Safari/537.36', 'Safari/537.36 Brave/1.60'),
         enumerable: true
      });
    }
  });
 } catch (braveErr) {
   if (braveErr.message.includes('Cannot redefine property')) {
     if (forceDebug) console.log(`[debug] Brave protection skipped (already applied): ${currentUrl}`);
   } else {
     console.warn(`[brave protection failed] ${currentUrl}: ${braveErr.message}`);
   }
 }
}

/**
 * Enhanced fingerprint protection with more realistic and varied spoofing
 * @param {import('puppeteer').Page} page - The Puppeteer page instance
 * @param {object} siteConfig - The site configuration object
 * @param {boolean} forceDebug - Whether debug logging is enabled
 * @param {string} currentUrl - The current URL being processed (for logging)
 * @returns {Promise<void>}
 */
async function applyFingerprintProtection(page, siteConfig, forceDebug, currentUrl) {
  const fingerprintSetting = siteConfig.fingerprint_protection;
  if (!fingerprintSetting) return;

  if (forceDebug) console.log(`[debug] Enhanced fingerprint_protection enabled for ${currentUrl}`);
  
  const spoof = fingerprintSetting === 'random' ? getRandomFingerprint() : {
    deviceMemory: 8, 
    hardwareConcurrency: 4,
    screen: { width: 1920, height: 1080, availWidth: 1920, availHeight: 1040, colorDepth: 24, pixelDepth: 24 },
    platform: DEFAULT_PLATFORM, 
    timezone: DEFAULT_TIMEZONE,
    language: 'en-US',
    cookieEnabled: true,
    doNotTrack: null
  };

  try {
    await page.evaluateOnNewDocument(({ spoof }) => {
     // Prevent duplicate execution
     if (window.__fingerprintProtectionApplied) {
       return;
     }
     window.__fingerprintProtectionApplied = true;
     
     const safeDefine = (obj, prop, descriptor) => {
       try {
         const existing = Object.getOwnPropertyDescriptor(obj, prop);
         if (existing && !existing.configurable) {
           return false;
         }
         Object.defineProperty(obj, prop, { configurable: true, ...descriptor });
         return true;
       } catch (e) {
         return false;
       }
     };
      // Enhanced property spoofing with more realistic values
      safeDefine(navigator, 'deviceMemory', { 
        get: () => spoof.deviceMemory,
        enumerable: true
      });
      
     safeDefine(navigator, 'hardwareConcurrency', { 
       get: () => spoof.hardwareConcurrency,
       enumerable: true
      });
      
      // Enhanced screen properties
      ['width', 'height', 'availWidth', 'availHeight', 'colorDepth', 'pixelDepth'].forEach(prop => {
        if (spoof.screen[prop] !== undefined) {
          safeDefine(window.screen, prop, { 
            get: () => spoof.screen[prop],
            enumerable: true
          });
        }
      });
      
      safeDefine(navigator, 'platform', { 
        get: () => spoof.platform,
        enumerable: true
      });
      
      // Enhanced timezone spoofing
      const originalDateTimeFormat = Intl.DateTimeFormat;
     safeDefine(window.Intl, 'DateTimeFormat', {
       value: function(...args) {
        const instance = new originalDateTimeFormat(...args);
        const originalResolvedOptions = instance.resolvedOptions;
        instance.resolvedOptions = function() {
          const options = originalResolvedOptions.call(this);
          options.timeZone = spoof.timezone;
          return options;
        };
        return instance;
       },
       writable: true
     });
      
      // Spoof Date.getTimezoneOffset
      const originalGetTimezoneOffset = Date.prototype.getTimezoneOffset;
     safeDefine(Date.prototype, 'getTimezoneOffset', {
       value: function() {
        // Return offset for spoofed timezone
        const timezoneOffsets = {
          'America/New_York': 300,    // EST offset
          'America/Los_Angeles': 480, // PST offset
          'Europe/London': 0,         // GMT offset
          'America/Chicago': 360      // CST offset
        };
        return timezoneOffsets[spoof.timezone] || originalGetTimezoneOffset.call(this);
       },
       writable: true
     });
      
      // Enhanced cookie and DNT spoofing
      if (spoof.cookieEnabled !== undefined) {
       safeDefine(navigator, 'cookieEnabled', {
         get: () => spoof.cookieEnabled
        });
      }
      
      if (spoof.doNotTrack !== undefined) {
       safeDefine(navigator, 'doNotTrack', {
         get: () => spoof.doNotTrack
        });
      }
      
    }, { spoof });
  } catch (err) {
   if (err.message.includes('Cannot redefine property')) {
     if (forceDebug) console.log(`[debug] Fingerprint protection skipped (already applied): ${currentUrl}`);
   } else {
    console.warn(`[enhanced fingerprint spoof failed] ${currentUrl}: ${err.message}`);
    }
  }
}

/**
 * Add mouse movement simulation to appear more human-like
 * @param {import('puppeteer').Page} page - The Puppeteer page instance
 * @param {boolean} forceDebug - Whether debug logging is enabled
 * @returns {Promise<void>}
 */
async function simulateHumanBehavior(page, forceDebug) {
  try {
    await page.evaluateOnNewDocument(() => {
     // Prevent duplicate execution
     if (window.__humanBehaviorApplied) {
       return;
     }
     window.__humanBehaviorApplied = true;
      // Simulate human-like mouse movements
      let mouseX = Math.random() * window.innerWidth;
      let mouseY = Math.random() * window.innerHeight;
      
      const moveInterval = setInterval(() => {
        mouseX += (Math.random() - 0.5) * 20;
        mouseY += (Math.random() - 0.5) * 20;
        
        mouseX = Math.max(0, Math.min(window.innerWidth, mouseX));
        mouseY = Math.max(0, Math.min(window.innerHeight, mouseY));
        
        document.dispatchEvent(new MouseEvent('mousemove', {
          clientX: mouseX,
          clientY: mouseY,
          bubbles: true
        }));
      }, 1000 + Math.random() * 2000);
      
      // Simulate occasional clicks and scrolls
      setTimeout(() => {
        if (Math.random() > 0.7) {
          document.dispatchEvent(new MouseEvent('click', {
            clientX: mouseX,
            clientY: mouseY,
            bubbles: true
          }));
        }
        
        // Simulate scroll events
        if (Math.random() > 0.8) {
          window.scrollBy(0, Math.random() * 100 - 50);
        }
      }, 5000 + Math.random() * 10000);
      
      // Stop simulation after 30 seconds to avoid detection
      setTimeout(() => {
        clearInterval(moveInterval);
      }, 30000);
    });
  } catch (err) {
   if (err.message.includes('Cannot redefine property')) {
     if (forceDebug) console.log(`[debug] Human behavior simulation skipped (already applied)`);
   } else {
    if (forceDebug) console.log(`[debug] Human behavior simulation failed: ${err.message}`);
    }
  }
}

/**
 * Enhanced main function that applies all fingerprint spoofing techniques
 * @param {import('puppeteer').Page} page - The Puppeteer page instance
 * @param {object} siteConfig - The site configuration object
 * @param {boolean} forceDebug - Whether debug logging is enabled
 * @param {string} currentUrl - The current URL being processed (for logging)
 * @returns {Promise<void>}
 */
async function applyAllFingerprintSpoofing(page, siteConfig, forceDebug, currentUrl) {
 try {
  await applyUserAgentSpoofing(page, siteConfig, forceDebug, currentUrl);
  await applyBraveSpoofing(page, siteConfig, forceDebug, currentUrl);
  await applyFingerprintProtection(page, siteConfig, forceDebug, currentUrl);
  
  // Add human behavior simulation if user agent spoofing is enabled
  if (siteConfig.userAgent) {
    await simulateHumanBehavior(page, forceDebug);
  }
 } catch (mainErr) {
   if (mainErr.message.includes('Cannot redefine property')) {
     if (forceDebug) console.log(`[debug] Fingerprint spoofing skipped (already applied): ${currentUrl}`);
   } else {
     console.warn(`[fingerprint spoofing failed] ${currentUrl}: ${mainErr.message}`);
   }
 }
}
// Export the safeDefineProperty helper for use by other modules
module.exports = {
  getRandomFingerprint,
  getRealisticScreenResolution,
  applyUserAgentSpoofing,
  applyBraveSpoofing,
  applyFingerprintProtection,
  applyAllFingerprintSpoofing,
  simulateHumanBehavior,
  safeDefineProperty,
  DEFAULT_PLATFORM,
  DEFAULT_TIMEZONE
};