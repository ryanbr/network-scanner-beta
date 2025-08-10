// redirect.js - Enhanced redirect handling module for nwss.js with Puppeteer 24.x optimizations
// Handles HTTP redirects, JavaScript redirects, meta refresh, and delayed redirects

/**
 * Enhanced navigation with comprehensive redirect detection including JavaScript redirects
 * Optimized for Puppeteer 24.x compatibility and performance
 * @param {Page} page - Puppeteer page instance
 * @param {string} currentUrl - Original URL to navigate to
 * @param {object} siteConfig - Site configuration
 * @param {object} gotoOptions - Computed goto options from existing logic
 * @param {boolean} forceDebug - Debug logging flag
 * @param {Function} formatLogMessage - Log formatting function from main script
 * @returns {Promise<{finalUrl: string, redirected: boolean, redirectChain: string[]}>}
 */
async function navigateWithRedirectHandling(page, currentUrl, siteConfig, gotoOptions = {}, forceDebug = false, formatLogMessage) {
  const redirectChain = [currentUrl];
  let finalUrl = currentUrl;
  let redirected = false;
  const jsRedirectTimeout = siteConfig.js_redirect_timeout || 5000;
  const maxRedirects = siteConfig.max_redirects || 10;
  const detectJSPatterns = siteConfig.detect_js_patterns !== false;

  // Enhanced timeout handling for 24.x
  const navigationTimeout = gotoOptions.timeout || 30000;
  const enhancedTimeout = Math.min(navigationTimeout * 1.2, 45000); // Cap at 45s for stability
  
  // Frame navigation handler with enhanced error handling for 24.x
  const navigationHandler = (frame) => {
    try {
      if (frame === page.mainFrame()) {
        const frameUrl = frame.url();
        if (frameUrl && frameUrl !== 'about:blank' && !redirectChain.includes(frameUrl)) {
          // Check redirect limit before adding
          if (redirectChain.length >= maxRedirects) {
            if (forceDebug) {
              console.log(formatLogMessage('debug', `Maximum redirects (${maxRedirects}) reached, stopping redirect chain`));
            }
            return;
          }
          redirectChain.push(frameUrl);
          finalUrl = frameUrl;
          redirected = true;
          
          if (forceDebug) {
            console.log(formatLogMessage('debug', `Frame navigation detected: ${frameUrl}`));
          }
        }
      }
    } catch (frameErr) {
      // Enhanced error handling for 24.x frame navigation issues
      if (forceDebug && !frameErr.message.includes('Execution context was destroyed')) {
        console.log(formatLogMessage('debug', `Frame navigation handler error: ${frameErr.message}`));
      }
    }
  };

  // Enhanced JavaScript redirect detector with 24.x compatibility
  const jsRedirectDetector = async () => {
    try {
      await page.evaluateOnNewDocument(() => {
        // Check if already injected to prevent conflicts in 24.x
        if (window._nwssRedirectDetectorInjected) return;
        window._nwssRedirectDetectorInjected = true;

        // Store original location methods with defensive checks
        const originalReplace = window.location.replace;
        const originalAssign = window.location.assign;
        const originalHrefDescriptor = Object.getOwnPropertyDescriptor(window.location, 'href');
        const originalHrefSetter = originalHrefDescriptor?.set;
        
        // Flag to track if JS redirect occurred
        window._jsRedirectDetected = false;
        window._jsRedirectUrl = null;
        window._jsRedirectType = null;
        
        // Enhanced error handling for location method interception
        const safeMethodOverride = (methodName, originalMethod, callback) => {
          try {
            window.location[methodName] = function(url) {
              callback(url, methodName);
              if (originalMethod) {
                return originalMethod.call(this, url);
              }
            };
          } catch (overrideErr) {
            console.log(`[jsRedirect] Failed to override ${methodName}:`, overrideErr.message);
          }
        };

        // Intercept location.replace() with enhanced error handling
        safeMethodOverride('replace', originalReplace, (url, method) => {
          window._jsRedirectDetected = true;
          window._jsRedirectUrl = url;
          window._jsRedirectType = `location.${method}`;
          console.log(`[jsRedirect] location.${method}:`, url);
        });
        
        // Intercept location.assign() with enhanced error handling
        safeMethodOverride('assign', originalAssign, (url, method) => {
          window._jsRedirectDetected = true;
          window._jsRedirectUrl = url;
          window._jsRedirectType = `location.${method}`;
          console.log(`[jsRedirect] location.${method}:`, url);
        });
        
        // Enhanced href setter interception with 24.x compatibility
        if (originalHrefSetter && originalHrefDescriptor) {
          try {
            Object.defineProperty(window.location, 'href', {
              set: function(url) {
                window._jsRedirectDetected = true;
                window._jsRedirectUrl = url;
                window._jsRedirectType = 'location.href';
                console.log('[jsRedirect] location.href set:', url);
                return originalHrefSetter.call(this, url);
              },
              get: originalHrefDescriptor.get || function() {
                return window.location.toString();
              },
              configurable: originalHrefDescriptor.configurable,
              enumerable: originalHrefDescriptor.enumerable
            });
          } catch (hrefErr) {
            console.log('[jsRedirect] Failed to override href setter:', hrefErr.message);
          }
        }
        
        // Enhanced meta refresh observer with better error handling
        const setupMetaObserver = () => {
          try {
            const observer = new MutationObserver((mutations) => {
              mutations.forEach((mutation) => {
                mutation.addedNodes.forEach((node) => {
                  if (node.nodeName === 'META' && 
                      node.getAttribute && 
                      node.getAttribute('http-equiv') === 'refresh') {
                    const content = node.getAttribute('content');
                    if (content) {
                      window._jsRedirectDetected = true;
                      window._jsRedirectUrl = content;
                      window._jsRedirectType = 'meta.refresh';
                      console.log('[jsRedirect] meta refresh:', content);
                    }
                  }
                });
              });
            });
            
            // Enhanced DOM ready detection for 24.x
            const startObserving = () => {
              if (document.head) {
                observer.observe(document.head, { childList: true, subtree: true });
                observer.observe(document.documentElement, { childList: true, subtree: true });
              }
            };

            if (document.readyState === 'loading') {
              document.addEventListener('DOMContentLoaded', startObserving);
            } else {
              startObserving();
            }
          } catch (observerErr) {
            console.log('[jsRedirect] Meta observer setup failed:', observerErr.message);
          }
        };

        setupMetaObserver();
      });
    } catch (jsErr) {
      if (forceDebug) {
        console.log(formatLogMessage('debug', `Failed to inject JS redirect detector: ${jsErr.message}`));
      }
    }
  };

  // Enhanced page error handling for 24.x
  const errorHandlers = {
    pageError: null,
    requestFailed: null
  };

  try {
    // Set up enhanced event listeners with 24.x error handling
    page.on('framenavigated', navigationHandler);
    
    // Enhanced page error handling for 24.x
    errorHandlers.pageError = (err) => {
      if (forceDebug) {
        const errorMessage = err?.message || err?.toString() || String(err) || 'Unknown redirect page error';
        console.log(formatLogMessage('debug', `Redirect page error: ${errorMessage}`));
      }
    };
    
    errorHandlers.requestFailed = (request) => {
      if (forceDebug) {
        try {
          const url = request?.url() || 'unknown URL';
          console.log(formatLogMessage('debug', `Redirect request failed: ${url}`));
        } catch (reqErr) {
          console.log(formatLogMessage('debug', `Redirect request failed: [URL extraction failed]`));
        }
      }
    };

    page.on('pageerror', errorHandlers.pageError);
    page.on('requestfailed', errorHandlers.requestFailed);
    
    // Inject JavaScript redirect detection
    await jsRedirectDetector();

    if (forceDebug && Object.keys(gotoOptions).length > 0) {
      console.log(formatLogMessage('debug', `Using goto options: ${JSON.stringify(gotoOptions)}`));
    }

    // Enhanced navigation with 24.x retry logic
    let navigationResponse = null;
    let navigationAttempts = 0;
    const maxNavigationAttempts = 2;

    while (navigationAttempts < maxNavigationAttempts) {
      try {
        navigationResponse = await Promise.race([
          page.goto(currentUrl, gotoOptions),
          new Promise((_, reject) => 
            setTimeout(() => reject(new Error('Navigation timeout')), enhancedTimeout)
          )
        ]);
        break; // Success, exit retry loop
      } catch (navErr) {
        navigationAttempts++;
        
        // 24.x specific error handling
        const isRetryableError = [
          'Navigation timeout',
          'Target.createTarget timed out',
          'Session closed',
          'Connection closed'
        ].some(errorMsg => navErr.message.includes(errorMsg));

        if (isRetryableError && navigationAttempts < maxNavigationAttempts) {
          if (forceDebug) {
            console.log(formatLogMessage('debug', `Navigation attempt ${navigationAttempts} failed, retrying: ${navErr.message}`));
          }
          await new Promise(resolve => setTimeout(resolve, 2000)); // Wait before retry
          continue;
        } else {
          throw navErr; // Re-throw non-retryable errors or max attempts reached
        }
      }
    }
    
    // Process navigation response
    if (navigationResponse && navigationResponse.url() !== currentUrl) {
      if (redirectChain.length >= maxRedirects) {
        if (forceDebug) {
          console.log(formatLogMessage('debug', `Maximum redirects (${maxRedirects}) reached during HTTP redirect`));
        }
        finalUrl = currentUrl;
      } else {
        finalUrl = navigationResponse.url();
        redirected = true;
        if (!redirectChain.includes(finalUrl)) redirectChain.push(finalUrl);
      }
      if (forceDebug) {
        console.log(formatLogMessage('debug', `HTTP redirect detected: ${currentUrl} ? ${finalUrl}`));
      }
    }

    // Enhanced JavaScript redirect detection with better timing for 24.x
    if (forceDebug) {
      console.log(formatLogMessage('debug', `Waiting ${jsRedirectTimeout}ms for potential JavaScript redirects...`));
    }
    
    let jsRedirectAttempts = 0;
    const maxJsRedirectAttempts = 3;
    const jsCheckInterval = Math.max(jsRedirectTimeout / maxJsRedirectAttempts, 1000);
    
    while (jsRedirectAttempts < maxJsRedirectAttempts) {
      await new Promise(resolve => setTimeout(resolve, jsCheckInterval));
      
      try {
        // Enhanced JavaScript redirect detection with better error handling
        const jsRedirectResult = await Promise.race([
          page.evaluate(() => {
            return {
              detected: window._jsRedirectDetected || false,
              url: window._jsRedirectUrl || null,
              type: window._jsRedirectType || null,
              currentUrl: window.location.href
            };
          }),
          new Promise((_, reject) => 
            setTimeout(() => reject(new Error('JS evaluation timeout')), 8000)
          )
        ]);
        
        // Check if URL changed through any means
        const currentPageUrl = page.url();
        if (currentPageUrl && currentPageUrl !== finalUrl && !redirectChain.includes(currentPageUrl)) {
          if (redirectChain.length >= maxRedirects) {
            if (forceDebug) {
              console.log(formatLogMessage('debug', `Maximum redirects (${maxRedirects}) reached during JS redirect detection`));
            }
            break;
          }
          redirectChain.push(currentPageUrl);
          finalUrl = currentPageUrl;
          redirected = true;
          
          if (forceDebug) {
            if (jsRedirectResult.detected) {
              console.log(formatLogMessage('debug', `JavaScript redirect detected (${jsRedirectResult.type}): ${jsRedirectResult.url || currentPageUrl}`));
            } else {
              console.log(formatLogMessage('debug', `URL change detected: ${currentPageUrl}`));
            }
          }
        }
        
        // Enhanced continuation logic for 24.x
        if (jsRedirectResult.detected && !redirected) {
          if (forceDebug) {
            console.log(formatLogMessage('debug', `JS redirect detected (${jsRedirectResult.type}) but not yet executed, waiting...`));
          }
          jsRedirectAttempts++;
          continue;
        }
        
        if (!jsRedirectResult.detected) {
          break;
        }
        
      } catch (evalErr) {
        if (forceDebug) {
          const isTimeoutError = evalErr.message.includes('JS evaluation timeout');
          const errorType = isTimeoutError ? 'timeout' : 'evaluation error';
          console.log(formatLogMessage('debug', `JS redirect check ${errorType}: ${evalErr.message}`));
        }
        
        // For 24.x, continue checking even after evaluation errors
        if (evalErr.message.includes('Execution context was destroyed')) {
          break; // Page was destroyed, no point continuing
        }
      }
      
      jsRedirectAttempts++;
    }

    // Optional: Detect common JavaScript redirect patterns in page source
    if (detectJSPatterns) {
      await detectCommonJSRedirects(page, forceDebug, formatLogMessage);
    }

    // Final URL check with enhanced error handling
    try {
      const finalPageUrl = page.url();
      if (finalPageUrl && finalPageUrl !== finalUrl) {
        if (redirectChain.length >= maxRedirects) {
          if (forceDebug) {
            console.log(formatLogMessage('debug', `Maximum redirects (${maxRedirects}) reached, keeping current finalUrl`));
          }
        } else {
          finalUrl = finalPageUrl;
          redirected = true;
          if (!redirectChain.includes(finalUrl)) {
            redirectChain.push(finalUrl);
          }
        }
      }
    } catch (urlCheckErr) {
      if (forceDebug) {
        console.log(formatLogMessage('debug', `Final URL check error: ${urlCheckErr.message}`));
      }
    }

  } finally {
    // Enhanced cleanup for 24.x compatibility
    try {
      page.off('framenavigated', navigationHandler);
      if (errorHandlers.pageError) page.off('pageerror', errorHandlers.pageError);
      if (errorHandlers.requestFailed) page.off('requestfailed', errorHandlers.requestFailed);
    } catch (cleanupErr) {
      if (forceDebug) {
        console.log(formatLogMessage('debug', `Event listener cleanup error: ${cleanupErr.message}`));
      }
    }
  }

  // Log redirect summary
  if (redirected && forceDebug) {
    console.log(formatLogMessage('debug', `Redirect chain: ${redirectChain.join(' ? ')}`));
  }

  // Extract redirect domains to exclude from matching
  let redirectDomains = [];
  if (redirected && redirectChain.length > 1) {
    const intermediateDomains = redirectChain.slice(0, -1).map(url => {
      try {
        return new URL(url).hostname;
      } catch {
        return null;
      }
    }).filter(Boolean);
    redirectDomains = intermediateDomains;
  }

  return { finalUrl, redirected, redirectChain, originalUrl: currentUrl, redirectDomains };
}

/**
 * Detect common JavaScript redirect patterns in page source
 * Enhanced for Puppeteer 24.x compatibility
 * @param {Page} page - Puppeteer page instance
 * @param {boolean} forceDebug - Debug logging flag
 * @param {Function} formatLogMessage - Log formatting function
 * @returns {Promise<Array>} Array of detected patterns
 */
async function detectCommonJSRedirects(page, forceDebug = false, formatLogMessage) {
  try {
    const redirectPatterns = await Promise.race([
      page.evaluate(() => {
        const patterns = [];
        
        // Enhanced pattern detection with better error handling
        try {
          const pageSource = document.documentElement.outerHTML;
          
          // Pattern 1: window.location = "url"
          const locationAssign = pageSource.match(/window\.location\s*=\s*["']([^"']+)["']/g);
          if (locationAssign) {
            patterns.push({ type: 'window.location assignment', matches: locationAssign });
          }
          
          // Pattern 2: location.href = "url"
          const hrefAssign = pageSource.match(/location\.href\s*=\s*["']([^"']+)["']/g);
          if (hrefAssign) {
            patterns.push({ type: 'location.href assignment', matches: hrefAssign });
          }
          
          // Pattern 3: setTimeout redirects
          const timeoutRedirect = pageSource.match(/setTimeout\s*\([^)]*location[^)]*\)/g);
          if (timeoutRedirect) {
            patterns.push({ type: 'setTimeout redirect', matches: timeoutRedirect });
          }
          
          // Pattern 4: Meta refresh (enhanced detection)
          const metaRefreshElements = document.querySelectorAll('meta[http-equiv="refresh"]');
          if (metaRefreshElements.length > 0) {
            const refreshContents = Array.from(metaRefreshElements).map(el => el.getAttribute('content')).filter(Boolean);
            if (refreshContents.length > 0) {
              patterns.push({ type: 'meta refresh', content: refreshContents });
            }
          }
          
          // Pattern 5: document.location redirects
          const docLocationAssign = pageSource.match(/document\.location\s*=\s*["']([^"']+)["']/g);
          if (docLocationAssign) {
            patterns.push({ type: 'document.location assignment', matches: docLocationAssign });
          }
          
          // Pattern 6: Enhanced history API redirects (new for 24.x)
          const historyRedirect = pageSource.match(/history\.(pushState|replaceState)\s*\([^)]*\)/g);
          if (historyRedirect) {
            patterns.push({ type: 'history API redirect', matches: historyRedirect });
          }
          
        } catch (patternErr) {
          console.log('[jsRedirect] Pattern detection error:', patternErr.message);
        }
        
        return patterns;
      }),
      new Promise((_, reject) => 
        setTimeout(() => reject(new Error('Pattern detection timeout')), 10000)
      )
    ]);
    
    if (redirectPatterns.length > 0 && forceDebug) {
      console.log(formatLogMessage('debug', `Found ${redirectPatterns.length} potential JS redirect pattern(s):`));
      redirectPatterns.forEach((pattern, idx) => {
        console.log(formatLogMessage('debug', `  [${idx + 1}] ${pattern.type}: ${JSON.stringify(pattern.matches || pattern.content)}`));
      });
    }
    
    return redirectPatterns;
    
  } catch (detectErr) {
    if (forceDebug) {
      console.log(formatLogMessage('debug', `Error detecting JS redirect patterns: ${detectErr.message}`));
    }
    return [];
  }
}

/**
 * Enhanced timeout error handling for partial redirects
 * Optimized for Puppeteer 24.x error scenarios
 * @param {Page} page - Puppeteer page instance
 * @param {string} originalUrl - Original URL that was requested
 * @param {Error} error - Navigation timeout error
 * @param {Function} safeGetDomain - Domain extraction function
 * @param {boolean} forceDebug - Debug logging flag
 * @param {Function} formatLogMessage - Log formatting function
 * @returns {Promise<{success: boolean, finalUrl: string, redirected: boolean}>}
 */
async function handleRedirectTimeout(page, originalUrl, error, safeGetDomain, forceDebug = false, formatLogMessage) {
  // Enhanced timeout error detection for 24.x
  const timeoutErrors = [
    'Navigation timeout',
    'Target.createTarget timed out',
    'Waiting for selector timed out',
    'Session closed',
    'Connection closed'
  ];
  
  const isTimeoutError = timeoutErrors.some(errorMsg => error.message.includes(errorMsg));
  
  if (!isTimeoutError) {
    return { success: false, finalUrl: originalUrl, redirected: false };
  }
  
  try {
    // Enhanced URL recovery with better error handling for 24.x
    const currentPageUrl = await Promise.race([
      Promise.resolve(page.url()),
      new Promise((_, reject) => 
        setTimeout(() => reject(new Error('URL check timeout')), 5000)
      )
    ]);
    
    if (currentPageUrl && 
        currentPageUrl !== 'about:blank' && 
        currentPageUrl !== originalUrl &&
        !currentPageUrl.startsWith('chrome-error://')) {
      
      const originalDomain = safeGetDomain(originalUrl);
      const currentDomain = safeGetDomain(currentPageUrl);
      
      if (originalDomain !== currentDomain) {
        if (forceDebug) {
          console.log(formatLogMessage('debug', `Partial redirect timeout recovered: ${originalDomain} ? ${currentDomain}`));
        }
        return { success: true, finalUrl: currentPageUrl, redirected: true };
      }
    }
    return { success: false, finalUrl: originalUrl, redirected: false };
  } catch (urlError) {
    if (forceDebug) {
      console.log(formatLogMessage('debug', `Error during timeout recovery: ${urlError.message}`));
    }
    return { success: false, finalUrl: originalUrl, redirected: false };
  }
}

module.exports = {
  navigateWithRedirectHandling,
  detectCommonJSRedirects,
  handleRedirectTimeout
};