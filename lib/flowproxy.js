/**
 * FlowProxy protection detection and handling module
 * Version: 1.0.0 - Enhanced with comprehensive documentation and smart detection
 * Detects flowProxy DDoS protection and handles it appropriately for security scanning
 * 
 * FlowProxy (by Aurologic) is a DDoS protection service similar to Cloudflare that:
 * - Implements rate limiting and browser verification
 * - Uses JavaScript challenges to verify legitimate browsers
 * - Can block automated tools and scrapers
 * - Requires specific handling for security scanning tools
 */

/**
 * Module version information
 */
const FLOWPROXY_MODULE_VERSION = '1.0.0';

/**
 * Timeout constants for FlowProxy operations (in milliseconds)
 */
const TIMEOUTS = {
  PAGE_LOAD_WAIT: 3000,           // Initial wait for page to load (increased for 24.x)
  JS_CHALLENGE_DEFAULT: 20000,    // Default JavaScript challenge timeout (increased for 24.x)
  RATE_LIMIT_DEFAULT: 30000,      // Default rate limit delay
  ADDITIONAL_DELAY_DEFAULT: 7000, // Default additional processing delay (increased for 24.x)
  PAGE_TIMEOUT_DEFAULT: 60000,    // Default page timeout (increased for 24.x)
  NAVIGATION_TIMEOUT_DEFAULT: 60000, // Default navigation timeout (increased for 24.x)
  FALLBACK_TIMEOUT: 5000          // Fallback timeout for failed operations
};

/**
 * Gets module version information
 * @returns {object} Version information object
 */
function getModuleInfo() {
  return {
    version: FLOWPROXY_MODULE_VERSION,
    name: 'FlowProxy Protection Handler'
  };
}

/**
 * Validates if a URL should be processed by FlowProxy protection
 * Only allows HTTP/HTTPS URLs, skips browser-internal and special protocols
 * 
 * @param {string} url - URL to validate
 * @param {boolean} forceDebug - Debug logging flag
 * @returns {boolean} True if URL should be processed
 * 
 * @example
 * // Valid URLs that will be processed
 * shouldProcessUrl('https://example.com') // => true
 * shouldProcessUrl('http://test.com') // => true
 * 
 * // Invalid URLs that will be skipped
 * shouldProcessUrl('chrome://settings') // => false
 * shouldProcessUrl('about:blank') // => false
 * shouldProcessUrl('file:///local/file.html') // => false
 */
function shouldProcessUrl(url, forceDebug = false) {
  if (!url || typeof url !== 'string') {
    if (forceDebug) console.log(`[flowproxy][url-validation] Skipping invalid URL: ${url}`);
    return false;
  }

  // Skip browser-internal and special protocol URLs
  // These protocols are not relevant for FlowProxy protection
  const skipPatterns = [
    'about:', 'chrome:', 'chrome-extension:', 'chrome-error:', 'chrome-search:',
    'devtools:', 'edge:', 'moz-extension:', 'safari-extension:', 'webkit:',
    'data:', 'blob:', 'javascript:', 'vbscript:', 'file:', 'ftp:', 'ftps:'
  ];

  const urlLower = url.toLowerCase();
  for (const pattern of skipPatterns) {
    if (urlLower.startsWith(pattern)) {
      if (forceDebug) {
        console.log(`[flowproxy][url-validation] Skipping ${pattern} URL: ${url.substring(0, 100)}${url.length > 100 ? '...' : ''}`);
      }
      return false;
    }
  }

  // Only process HTTP/HTTPS URLs - FlowProxy only protects web traffic
  if (!urlLower.startsWith('http://') && !urlLower.startsWith('https://')) {
    if (forceDebug) {
      console.log(`[flowproxy][url-validation] Skipping non-HTTP(S) URL: ${url.substring(0, 100)}${url.length > 100 ? '...' : ''}`);
    }
    return false;
  }

  return true;
}

/**
 * Detects Puppeteer version and capabilities for enhanced 24.x compatibility
 * @returns {object} Version detection information
 */
function detectPuppeteerCapabilities() {
  try {
    const puppeteer = require('puppeteer');
    // Enhanced version detection for better accuracy
    const hasLegacyLauncher = puppeteer._launcher?.defaultArgs;
    const hasModernLauncher = puppeteer.launch && !hasLegacyLauncher;
    
    // Check for 24.x specific APIs
    const has24xAPIs = typeof puppeteer.Browser?.version === 'function' || 
                      typeof puppeteer.launch?.toString().includes('new') !== 'undefined';
    
    const version = hasLegacyLauncher ? 'legacy' : 'modern';
    
    return {
      is24x: version === 'modern' || has24xAPIs,
      needsEnhancedTimeouts: version === 'modern' || has24xAPIs,
      supportsNewHeadless: version === 'modern' || has24xAPIs,
      detectionMethod: hasLegacyLauncher ? 'launcher' : has24xAPIs ? 'api' : 'fallback'
   };
  } catch (error) {
    // Fallback assumptions for unknown versions
    return {
      is24x: true, // Assume modern version
      needsEnhancedTimeouts: true,
      supportsNewHeadless: true,
      detectionMethod: 'error-fallback'
    };
  }
}

/**
 * Enhanced version-aware timeout constants
 */
const PUPPETEER_INFO = detectPuppeteerCapabilities();
const ENHANCED_TIMEOUTS = PUPPETEER_INFO.needsEnhancedTimeouts ? {
  PAGE_LOAD_WAIT: Math.round(TIMEOUTS.PAGE_LOAD_WAIT * 1.5),
  JS_CHALLENGE_DEFAULT: Math.round(TIMEOUTS.JS_CHALLENGE_DEFAULT * 1.3),
  ADDITIONAL_DELAY_DEFAULT: Math.round(TIMEOUTS.ADDITIONAL_DELAY_DEFAULT * 1.4),
  PAGE_TIMEOUT_DEFAULT: Math.round(TIMEOUTS.PAGE_TIMEOUT_DEFAULT * 1.3),
  NAVIGATION_TIMEOUT_DEFAULT: Math.round(TIMEOUTS.NAVIGATION_TIMEOUT_DEFAULT * 1.3),
  RATE_LIMIT_DEFAULT: TIMEOUTS.RATE_LIMIT_DEFAULT // Rate limits don't need adjustment
} : TIMEOUTS;

// Add RATE_LIMIT_DEFAULT to base TIMEOUTS if not already enhanced
if (!PUPPETEER_INFO.needsEnhancedTimeouts) {
  ENHANCED_TIMEOUTS.RATE_LIMIT_DEFAULT = TIMEOUTS.RATE_LIMIT_DEFAULT;
}

/**
 * Cross-version compatible timeout function for Puppeteer with timeout protection
 * Handles different Puppeteer versions that may have different timeout methods
 * 
 * @param {import('puppeteer').Page} page - Puppeteer page instance
 * @param {number} timeout - Timeout in milliseconds
 * @returns {Promise<void>}
 * 
 * @example
 * // Wait for 5 seconds
 * await waitForTimeout(page, 5000);
 */
async function waitForTimeout(page, timeout) {
  try {
    // Enhanced timeout for 24.x compatibility
    const adjustedTimeout = PUPPETEER_INFO.needsEnhancedTimeouts ? 
      Math.max(timeout, 1000) : timeout; // Minimum 1s for 24.x stability
    
    // Try newer Puppeteer method first (v1.4.0+/24.x)
    if (typeof page.waitForTimeout === 'function') {
      await page.waitForTimeout(adjustedTimeout);
    } else if (page.waitFor && typeof page.waitFor === 'function') {
      // Fallback for older Puppeteer versions
      await page.waitFor(adjustedTimeout);
    } else if (page.waitForSelector && typeof page.waitForSelector === 'function') {
      // Alternative fallback using waitForSelector with timeout
      try {
        await page.waitForSelector('body', { timeout: Math.min(adjustedTimeout, 5000) });
        if (adjustedTimeout > 5000) {
          await new Promise(resolve => setTimeout(resolve, adjustedTimeout - 5000));
        }
      } catch (selectorErr) {
        // If selector fails, just use setTimeout
        await new Promise(resolve => setTimeout(resolve, adjustedTimeout));
      }
    } else {
      // Final fallback - use standard setTimeout
      await new Promise(resolve => setTimeout(resolve, adjustedTimeout));
    }
  } catch (error) {
    // Enhanced error handling for 24.x specific errors
    const is24xError = error.message.includes('Runtime.callFunctionOn timed out') ||
                      error.message.includes('Execution context was destroyed') ||
                      error.message.includes('Target.closeTarget timed out') ||
                      error.message.includes('Navigation timeout') ||
                      error.message.includes('Protocol error');
    
    if (is24xError) {
      // Use progressive backoff for 24.x errors
      const backoffTimeout = Math.min(Math.max(timeout * 1.8, 3000), 15000); // Cap at 15s
      await new Promise(resolve => setTimeout(resolve, backoffTimeout));
      return;
    }
    // If all else fails, use setTimeout
    await new Promise(resolve => setTimeout(resolve, timeout));
  }
}

/**
 * Analyzes the current page to detect flowProxy protection with comprehensive detection logic
 * 
 * FlowProxy protection typically manifests as:
 * - DDoS protection pages with "Please wait" messages
 * - Rate limiting responses (429 errors)
 * - JavaScript challenges that must complete before access
 * - Aurologic branding and flowproxy-specific elements
 * - Browser verification processes
 * 
 * @param {import('puppeteer').Page} page - Puppeteer page instance
 * @returns {Promise<object>} Detection information object with detailed analysis
 * 
 * @example
 * const analysis = await analyzeFlowProxyProtection(page);
 * if (analysis.isFlowProxyDetected) {
 *   console.log(`FlowProxy protection found: ${analysis.title}`);
 *   if (analysis.isRateLimited) {
 *     console.log('Rate limiting is active');
 *   }
 * }
 */
async function analyzeFlowProxyProtection(page) {
  try {
    // Get current page URL and validate it first
    const currentPageUrl = await page.url();
    
    if (!shouldProcessUrl(currentPageUrl, false)) {
      return {
        isFlowProxyDetected: false,
        skippedInvalidUrl: true,
        url: currentPageUrl
      };
    }

    // Continue with comprehensive FlowProxy detection for valid HTTP(S) URLs
    return await page.evaluate(() => {
      const title = document.title || '';
      const bodyText = document.body ? document.body.textContent : '';
      const url = window.location.href;
      
      // Check for flowProxy/aurologic specific domain indicators
      // FlowProxy services often redirect to aurologic domains or use flowproxy subdomains
      const hasFlowProxyDomain = url.includes('aurologic') || 
                                 url.includes('flowproxy') ||
                                 url.includes('ddos-protection');
      
      // Check for flowProxy challenge page indicators
      // These are common titles and text patterns used by FlowProxy protection pages
      const hasProtectionPage = title.includes('DDoS Protection') ||
                               title.includes('Please wait') ||
                               title.includes('Checking your browser') ||
                               bodyText.includes('DDoS protection by aurologic') ||
                               bodyText.includes('flowProxy') ||
                               bodyText.includes('Verifying your browser');
      
      // Check for specific flowProxy DOM elements
      // FlowProxy typically adds custom data attributes and CSS classes
      const hasFlowProxyElements = document.querySelector('[data-flowproxy]') !== null ||
                                  document.querySelector('.flowproxy-challenge') !== null ||
                                  document.querySelector('#flowproxy-container') !== null ||
                                  document.querySelector('.aurologic-protection') !== null;
      
      // Check for challenge indicators
      // FlowProxy uses various elements to indicate active challenges
      const hasChallengeElements = document.querySelector('.challenge-running') !== null ||
                                  document.querySelector('.verification-container') !== null ||
                                  document.querySelector('input[name="flowproxy-response"]') !== null;
      
      // Check for rate limiting indicators
      // Rate limiting is a common FlowProxy feature that shows specific messages
      const isRateLimited = bodyText.includes('Rate limited') ||
                           bodyText.includes('Too many requests') ||
                           bodyText.includes('Please try again later') ||
                           title.includes('429') ||
                           title.includes('Rate Limit');
      
      // Check for JavaScript challenge indicators
      // FlowProxy often requires JavaScript to be enabled and uses specific scripts
      const hasJSChallenge = document.querySelector('script[src*="flowproxy"]') !== null ||
                            document.querySelector('script[src*="aurologic"]') !== null ||
                            bodyText.includes('JavaScript is required') ||
                            bodyText.includes('Please enable JavaScript');
      
      // Check for loading/processing indicators
      // FlowProxy shows these while performing browser verification
      const isProcessing = bodyText.includes('Processing') ||
                          bodyText.includes('Loading') ||
                          document.querySelector('.loading-spinner') !== null ||
                          document.querySelector('.processing-indicator') !== null;
      
      // Main detection logic - any of these primary indicators suggest FlowProxy presence
      const isFlowProxyDetected = hasFlowProxyDomain || 
                                 hasProtectionPage || 
                                 hasFlowProxyElements || 
                                 hasChallengeElements;
      
      return {
        isFlowProxyDetected,
        hasFlowProxyDomain,
        hasProtectionPage,
        hasFlowProxyElements,
        hasChallengeElements,
        isRateLimited,
        hasJSChallenge,
        isProcessing,
        title,
        url,
        bodySnippet: bodyText.substring(0, 200) // First 200 chars for debugging
      };
    });
  } catch (error) {
    // Return safe defaults if page evaluation fails
    return {
      isFlowProxyDetected: false,
      hasFlowProxyDomain: false,
      hasProtectionPage: false,
      hasFlowProxyElements: false,
      hasChallengeElements: false,
      isRateLimited: false,
      hasJSChallenge: false,
      isProcessing: false,
      error: error.message
    };
  }
}

/**
 * Handles flowProxy protection by implementing appropriate delays and retry logic
 * 
 * FlowProxy handling strategy:
 * 1. Detect protection type (rate limiting, JS challenge, etc.)
 * 2. Implement appropriate delays based on protection type
 * 3. Wait for JavaScript challenges to complete
 * 4. Verify successful bypass before continuing
 * 
 * @param {import('puppeteer').Page} page - Puppeteer page instance
 * @param {string} currentUrl - Current URL being processed
 * @param {object} siteConfig - Site configuration object with FlowProxy settings
 * @param {boolean} forceDebug - Debug mode flag for detailed logging
 * @param {object} puppeteerInfo - Optional Puppeteer version information
 * 
 * @returns {Promise<object>} Result object with comprehensive handling details:
 * {
 *   flowProxyDetection: {
 *     attempted: boolean,     // Whether detection was attempted
 *     detected: boolean,      // Whether FlowProxy protection was found
 *     details: object|null    // Detailed detection information
 *   },
 *   handlingResult: {
 *     attempted: boolean,     // Whether handling was attempted
 *     success: boolean        // Whether handling succeeded
 *   },
 *   overallSuccess: boolean,  // True if no critical failures occurred
 *   errors: string[],         // Array of error messages
 *   warnings: string[],       // Array of warning messages
 *   skippedInvalidUrl: boolean // True if URL was skipped due to invalid protocol
 * }
 * 
 * @example
 * const config = {
 *   flowproxy_delay: 45000,           // Rate limit delay (45 seconds)
 *   flowproxy_js_timeout: 20000,      // JS challenge timeout (20 seconds)
 *   flowproxy_additional_delay: 8000  // Additional processing delay (8 seconds)
 * };
 * 
 * const result = await handleFlowProxyProtection(page, url, config, true);
 * if (result.flowProxyDetection.detected) {
 *   console.log('FlowProxy protection handled');
 *   if (result.warnings.length > 0) {
 *     console.log('Warnings:', result.warnings);
 *   }
 * }
 */
async function handleFlowProxyProtection(page, currentUrl, siteConfig, forceDebug = false, puppeteerInfo = null) {
  const versionInfo = puppeteerInfo || PUPPETEER_INFO;
  
  // Enhanced debug logging for version detection
  if (forceDebug && versionInfo.detectionMethod) {
    console.log(`[debug][flowproxy] Puppeteer detection: ${versionInfo.detectionMethod}, 24.x: ${versionInfo.is24x}`);
  }

  // VALIDATE URL FIRST - Skip protection handling for non-HTTP(S) URLs
  // FlowProxy only protects web traffic, so other protocols should be skipped
  if (!shouldProcessUrl(currentUrl, forceDebug)) {
    if (forceDebug) {
      console.log(`[debug][flowproxy] Skipping protection handling for non-HTTP(S) URL: ${currentUrl}`);
    }
    return {
      flowProxyDetection: { attempted: false, detected: false },
      handlingResult: { attempted: false, success: true },
      overallSuccess: true,
      errors: [],
      warnings: [],
      skippedInvalidUrl: true
    };
  }

  // Initialize result structure for tracking all handling aspects
  const result = {
    flowProxyDetection: { attempted: false, detected: false },
    handlingResult: { attempted: false, success: false },
    overallSuccess: true,
    errors: [],
    warnings: []
  };

  // Use enhanced timeouts for 24.x
  const timeouts = versionInfo.needsEnhancedTimeouts ? ENHANCED_TIMEOUTS : TIMEOUTS;
  
  if (forceDebug) {
    const timeoutMode = versionInfo.needsEnhancedTimeouts ? 'enhanced (24.x)' : 'standard';
    console.log(`[debug][flowproxy] Using ${timeoutMode} timeouts - Page: ${timeouts.PAGE_LOAD_WAIT}ms, JS: ${timeouts.JS_CHALLENGE_DEFAULT}ms`);
    if (versionInfo.needsEnhancedTimeouts) {
      console.log(`[debug][flowproxy] Enhanced timeout multipliers applied for 24.x stability`);
    }
  }

  try {
    if (forceDebug) console.log(`[debug][flowproxy] Checking for flowProxy protection on ${currentUrl}`);
    
    // Wait for initial page load before analyzing
    // FlowProxy protection pages need time to fully render their elements
    await waitForTimeout(page, timeouts.PAGE_LOAD_WAIT);

    // Perform comprehensive FlowProxy detection
    const detectionInfo = await analyzeFlowProxyProtection(page);
    result.flowProxyDetection = { 
      attempted: true, 
      detected: detectionInfo.isFlowProxyDetected,
      details: detectionInfo 
    };
    
    // Only proceed with handling if FlowProxy protection is detected
    if (detectionInfo.isFlowProxyDetected) {
      result.handlingResult.attempted = true;
      
      if (forceDebug) {
        console.log(`[debug][flowproxy] FlowProxy protection detected on ${currentUrl}:`);
        console.log(`[debug][flowproxy]   Page Title: "${detectionInfo.title}"`);
        console.log(`[debug][flowproxy]   Current URL: ${detectionInfo.url}`);
        console.log(`[debug][flowproxy]   Has Protection Page: ${detectionInfo.hasProtectionPage}`);
        console.log(`[debug][flowproxy]   Has Challenge Elements: ${detectionInfo.hasChallengeElements}`);
        console.log(`[debug][flowproxy]   Is Rate Limited: ${detectionInfo.isRateLimited}`);
        console.log(`[debug][flowproxy]   Has JS Challenge: ${detectionInfo.hasJSChallenge}`);
        console.log(`[debug][flowproxy]   Is Processing: ${detectionInfo.isProcessing}`);
        console.log(`[debug][flowproxy]   Body Snippet: "${detectionInfo.bodySnippet}"`);
      }

      // HANDLE RATE LIMITING - Highest priority as it blocks all requests
      // Rate limiting requires waiting before any other actions
      if (detectionInfo.isRateLimited) {
        const rateLimitDelay = siteConfig.flowproxy_delay || (timeouts.RATE_LIMIT_DEFAULT || TIMEOUTS.RATE_LIMIT_DEFAULT);
        result.warnings.push(`Rate limiting detected - implementing ${rateLimitDelay}ms delay`);
        if (forceDebug) console.log(`[debug][flowproxy] Rate limiting detected, waiting ${rateLimitDelay}ms`);
        await waitForTimeout(page, rateLimitDelay);
      }

      // HANDLE JAVASCRIPT CHALLENGES - Second priority as they must complete
      // FlowProxy uses JS challenges to verify browser legitimacy
      if (detectionInfo.hasJSChallenge || detectionInfo.isProcessing) {
        const jsWaitTime = siteConfig.flowproxy_js_timeout || (timeouts.JS_CHALLENGE_DEFAULT || TIMEOUTS.JS_CHALLENGE_DEFAULT);
        if (forceDebug) console.log(`[debug][flowproxy] JavaScript challenge detected, waiting up to ${jsWaitTime}ms for completion`);
        
        try {
          // Wait for challenge completion indicators to disappear
          // These conditions indicate the JS challenge has finished
          await page.waitForFunction(
            () => {
              const bodyText = document.body ? document.body.textContent : '';
              return !bodyText.includes('Processing') && 
                     !bodyText.includes('Checking your browser') &&
                     !bodyText.includes('Please wait') &&
                     !document.querySelector('.loading-spinner') &&
                     !document.querySelector('.processing-indicator');
            },
            { timeout: jsWaitTime }
          );
          
          if (forceDebug) console.log(`[debug][flowproxy] JavaScript challenge appears to have completed`);
        } catch (timeoutErr) {
          // Continue even if timeout occurs - some challenges may take longer
          const is24xTimeoutError = [
            'Runtime.callFunctionOn timed out',
            'Execution context was destroyed',
            'Navigation timeout',
            'waitForFunction timed out'
          ].some(pattern => timeoutErr.message.includes(pattern));
          
          if (is24xTimeoutError && versionInfo.needsEnhancedTimeouts) {
            result.warnings.push(`JavaScript challenge timeout (24.x compatibility) after ${jsWaitTime}ms - applying fallback`);
            if (forceDebug) console.log(`[debug][flowproxy] 24.x timeout detected - implementing fallback delay`);
            await waitForTimeout(page, timeouts.ADDITIONAL_DELAY_DEFAULT);
          } else {
            result.warnings.push(`JavaScript challenge timeout after ${jsWaitTime}ms`);
            if (forceDebug) console.log(`[debug][flowproxy] JavaScript challenge timeout - continuing anyway`);
          }
        }
      }

      // IMPLEMENT ADDITIONAL DELAY - Final step to ensure all processing completes
      // FlowProxy may need extra time even after challenges complete
      const additionalDelay = siteConfig.flowproxy_additional_delay || (timeouts.ADDITIONAL_DELAY_DEFAULT || TIMEOUTS.ADDITIONAL_DELAY_DEFAULT);
      if (forceDebug) console.log(`[debug][flowproxy] Implementing additional ${additionalDelay}ms delay for flowProxy processing`);
      await waitForTimeout(page, additionalDelay);

      // VERIFY SUCCESSFUL BYPASS - Check if we're still on a protection page
      // This helps identify if our handling was successful
      const finalCheck = await analyzeFlowProxyProtection(page);
      if (finalCheck.isFlowProxyDetected && finalCheck.hasProtectionPage) {
        result.warnings.push('Still on flowProxy protection page after handling attempts');
        if (forceDebug) console.log(`[debug][flowproxy] Warning: Still appears to be on protection page`);
        // Don't mark as failure - protection page may persist but still allow access
      } else {
        result.handlingResult.success = true;
        if (forceDebug) console.log(`[debug][flowproxy] Successfully handled flowProxy protection for ${currentUrl}`);
      }
      
    } else {
      // No FlowProxy protection detected - mark as successful (nothing to handle)
      if (forceDebug) console.log(`[debug][flowproxy] No flowProxy protection detected on ${currentUrl}`);
      result.overallSuccess = true;
    }
    
  } catch (error) {
    // Critical error occurred during handling
    const is24xCriticalError = [
      'Runtime.callFunctionOn timed out',
      'Execution context was destroyed',
      'Target.closeTarget timed out',
      'Protocol error',
      'Session closed',
      'Navigation timeout',
      'Page crashed',
      'Connection closed'
    ].some(pattern => error.message.includes(pattern));
    
    if (is24xCriticalError) {
      result.errors.push(`FlowProxy handling error (24.x): ${error.message}`);
    } else {
      result.errors.push(`FlowProxy handling error: ${error.message}`);
    }
    result.overallSuccess = false;
    if (forceDebug) {
      console.log(`[debug][flowproxy] FlowProxy handling failed for ${currentUrl}:`);
      console.log(`[debug][flowproxy]   Error: ${error.message}`);
      if (is24xCriticalError) {
        console.log(`[debug][flowproxy]   Error Type: 24.x compatibility issue`);
        console.log(`[debug][flowproxy]   Suggestion: Consider increasing timeouts or reducing concurrency`);
      }
      console.log(`[debug][flowproxy]   Stack: ${error.stack}`);
    }
  }

  // LOG COMPREHENSIVE RESULTS for debugging and monitoring
  if (result.errors.length > 0 && forceDebug) {
    console.log(`[debug][flowproxy] FlowProxy handling completed with errors for ${currentUrl}:`);
    result.errors.forEach(error => {
      console.log(`[debug][flowproxy]   - ${error}`);
    });
  } else if (result.warnings.length > 0 && forceDebug) {
    console.log(`[debug][flowproxy] FlowProxy handling completed with warnings for ${currentUrl}:`);
    result.warnings.forEach(warning => {
      console.log(`[debug][flowproxy]   - ${warning}`);
    });
  } else if (result.flowProxyDetection.attempted && forceDebug) {
    console.log(`[debug][flowproxy] FlowProxy handling completed successfully for ${currentUrl}`);
  }

  return result;
}

/**
 * Quick check to determine if the current page might be behind flowProxy protection
 * This is a lightweight alternative to full analysis for simple detection needs
 * 
 * @param {import('puppeteer').Page} page - Puppeteer page instance
 * @returns {Promise<boolean>} True if flowProxy protection is suspected
 * 
 * @example
 * if (await isFlowProxyProtected(page)) {
 *   console.log('FlowProxy protection detected - implementing handling');
 *   await handleFlowProxyProtection(page, url, config);
 * }
 */
async function isFlowProxyProtected(page) {
  try {
    const detection = await analyzeFlowProxyProtection(page);
    return detection.isFlowProxyDetected;
  } catch (error) {
    // Return false if detection fails - assume no protection
    return false;
  }
}

/**
 * Gets recommended timeout values for flowProxy protected sites
 * Provides sensible defaults while allowing site-specific customization
 * 
 * @param {object} siteConfig - Site configuration object with optional FlowProxy settings
 * @returns {object} Recommended timeout values for FlowProxy handling
 * 
 * @example
 * const timeouts = getFlowProxyTimeouts({
 *   flowproxy_delay: 60000,        // Custom rate limit delay
 *   flowproxy_js_timeout: 25000    // Custom JS challenge timeout
 * });
 * 
 * // Use timeouts in page operations
 * await page.goto(url, { timeout: timeouts.pageTimeout });
 */
function getFlowProxyTimeouts(siteConfig) {
  const timeouts = PUPPETEER_INFO.needsEnhancedTimeouts ? ENHANCED_TIMEOUTS : TIMEOUTS;
  
  return {
    pageTimeout: siteConfig.flowproxy_page_timeout || timeouts.PAGE_TIMEOUT_DEFAULT,
    navigationTimeout: siteConfig.flowproxy_nav_timeout || (timeouts.NAVIGATION_TIMEOUT_DEFAULT || TIMEOUTS.NAVIGATION_TIMEOUT_DEFAULT),
    challengeTimeout: siteConfig.flowproxy_js_timeout || (timeouts.JS_CHALLENGE_DEFAULT || TIMEOUTS.JS_CHALLENGE_DEFAULT),
    rateLimit: siteConfig.flowproxy_delay || (timeouts.RATE_LIMIT_DEFAULT || TIMEOUTS.RATE_LIMIT_DEFAULT),
    additionalDelay: siteConfig.flowproxy_additional_delay || (timeouts.ADDITIONAL_DELAY_DEFAULT || TIMEOUTS.ADDITIONAL_DELAY_DEFAULT),
    // Add version information for external use
    puppeteerVersion: PUPPETEER_INFO,
    // Add timeout calculation details for debugging
    timeoutSource: PUPPETEER_INFO.needsEnhancedTimeouts ? 'enhanced' : 'standard',
    enhancementFactors: PUPPETEER_INFO.needsEnhancedTimeouts ? {
      pageLoad: 1.5,
      jsChallenge: 1.3,
      additional: 1.4,
      navigation: 1.3
    } : null
  };
}

// Export all public functions for use in other modules
module.exports = {
  analyzeFlowProxyProtection,
  handleFlowProxyProtection,
  isFlowProxyProtected,
  getFlowProxyTimeouts,
  detectPuppeteerCapabilities,
  waitForTimeout,
  getModuleInfo,
  FLOWPROXY_MODULE_VERSION
};