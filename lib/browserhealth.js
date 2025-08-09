/**
 * Browser health monitoring module for nwss.js
 * Provides health checks and recovery mechanisms to prevent protocol timeouts
 */

const { formatLogMessage, messageColors } = require('./colorize');

/**
 * Detects Puppeteer version for compatibility adjustments
 * @returns {object} Version information and compatibility flags
 */
function detectPuppeteerVersion() {
  try {
    const puppeteer = require('puppeteer');
    const version = puppeteer.version || '';
    const majorVersion = parseInt(version.split('.')[0]) || 20;
    
    return {
      version,
      majorVersion,
      is24x: majorVersion >= 24,
      needsEnhancedTimeouts: majorVersion >= 24
    };
  } catch (err) {
    return { version: 'unknown', majorVersion: 20, is24x: false, needsEnhancedTimeouts: false };
  }
}

/**
 * Checks if browser instance is still responsive
 * @param {import('puppeteer').Browser} browserInstance - Puppeteer browser instance
 * @param {number} timeout - Timeout in milliseconds (default: 5000)
 * @returns {Promise<object>} Health check result
 */
async function checkBrowserHealth(browserInstance, timeout = 5000) {
  const versionInfo = detectPuppeteerVersion();
  const baseTimeout = versionInfo.needsEnhancedTimeouts ? Math.max(timeout, 8000) : timeout;

  const healthResult = {
    healthy: false,
    pageCount: 0,
    error: null,
    responseTime: 0,
    recommendations: [],
    criticalError: false
  };

  const startTime = Date.now();

  try {
    // Test 1: Check if browser is connected
    if (!browserInstance || browserInstance.process() === null) {
      healthResult.error = 'Browser process not running';
      healthResult.recommendations.push('Create new browser instance');
      healthResult.criticalError = true;
      return healthResult;
    }

    // Test 2: Try to get pages list with timeout
    const pages = await Promise.race([
      browserInstance.pages(),
      new Promise((_, reject) => 
        setTimeout(() => reject(new Error('Browser unresponsive - pages() timeout')), baseTimeout)
      )
    ]);

    healthResult.pageCount = pages.length;
    healthResult.responseTime = Date.now() - startTime;

    // Test 3: Check for excessive pages (memory leak indicator)
    if (pages.length > 20) {
      healthResult.recommendations.push('Too many open pages - consider browser restart');
    }

    // Test 4: Try to create a test page to verify browser functionality
    let testPage = null;
    try {
        // Dynamic timeout adjustment based on version
        const pageTimeout = versionInfo.needsEnhancedTimeouts ? baseTimeout * 2 : baseTimeout * 1.5;
        
        testPage = await Promise.race([
        browserInstance.newPage(),
        new Promise((_, reject) => 
            setTimeout(() => reject(new Error('Page creation timeout')), pageTimeout)
        )
      ]);

      // Quick test navigation to about:blank
      await Promise.race([
        testPage.goto('about:blank'),
        new Promise((_, reject) => 
          setTimeout(() => reject(new Error('Navigation timeout')), baseTimeout)
        )
      ]);

      // Add timeout wrapper for Puppeteer 24.x page.close() compatibility  
      await Promise.race([
        testPage.close(),
        new Promise((_, reject) => 
          setTimeout(() => reject(new Error('Test page close timeout')), 5000)
        )
      ]);
      
    } catch (pageTestError) {
      if (testPage && !testPage.isClosed()) {
        try { 
          // Emergency close with timeout wrapper
          await Promise.race([
            testPage.close(),
            new Promise((_, reject) => 
              setTimeout(() => reject(new Error('Emergency close timeout')), 3000)
            )
          ]);
        } catch (e) { /* ignore timeout on emergency close */ }
      }
      healthResult.error = `Page creation/navigation failed: ${pageTestError.message}`;
      if (isCriticalProtocolError(pageTestError)) {
        healthResult.recommendations.push('Browser restart required - critical protocol error');
        healthResult.criticalError = true;
      } else {
        healthResult.recommendations.push('Browser restart recommended');
      }
      return healthResult;
    }

    // Test 5: Check response time performance
    if (healthResult.responseTime > 2000) {
      healthResult.recommendations.push('Slow browser response - consider restart');
    }

    // If all tests pass
    healthResult.healthy = true;

  } catch (error) {
    healthResult.error = error.message;
    healthResult.responseTime = Date.now() - startTime;
    
    // Categorize error types for better recommendations
    if (error.message.includes('Runtime.callFunctionOn timed out') || 
        error.message.includes('Protocol error') || 
        error.message.includes('Target closed')) {
      healthResult.recommendations.push('Browser restart required - critical protocol error');
      healthResult.criticalError = true;
    } else if (error.message.includes('timeout') || error.message.includes('unresponsive')) {
      healthResult.recommendations.push('Browser restart required - unresponsive');
      healthResult.criticalError = true;
    } else {
      healthResult.recommendations.push('Browser restart recommended - unknown error');
    }
  }

  return healthResult;
}

/**
 * Checks memory usage of browser process (if available)
 * @param {import('puppeteer').Browser} browserInstance - Puppeteer browser instance
 * @param {number} timeout - Optional timeout override
 * @returns {Promise<object>} Memory usage information
 */
async function checkBrowserMemory(browserInstance) {
  const memoryResult = {
    available: false,
    usage: null,
    error: null,
    recommendations: []
  };

  try {
    const browserProcess = browserInstance.process();
    if (!browserProcess || !browserProcess.pid) {
      memoryResult.error = 'No browser process available';
      return memoryResult;
    }

    // Try to get process memory info (Linux/Unix)
    try {
      const { execSync } = require('child_process');
      const memInfo = execSync(`ps -p ${browserProcess.pid} -o rss=`, { encoding: 'utf8', timeout: 2000 });
      const memoryKB = parseInt(memInfo.trim());
      
      if (!isNaN(memoryKB)) {
        const memoryMB = Math.round(memoryKB / 1024);
        memoryResult.available = true;
        memoryResult.usage = {
          rss: memoryKB,
          rssMB: memoryMB
        };

        // Memory usage recommendations
        if (memoryMB > 1000) {
          memoryResult.recommendations.push(`High memory usage: ${memoryMB}MB - restart recommended`);
        } else if (memoryMB > 500) {
          memoryResult.recommendations.push(`Elevated memory usage: ${memoryMB}MB - monitor closely`);
        }
      }
    } catch (psError) {
      memoryResult.error = `Memory check failed: ${psError.message}`;
    }

  } catch (error) {
    memoryResult.error = error.message;
  }

  return memoryResult;
}

 /**
 * Detects critical protocol errors that require immediate browser restart
 */
function isCriticalProtocolError(error) {
  if (!error || !error.message) return false;
  
  const criticalErrors = [
    'Runtime.callFunctionOn timed out',
    'Protocol error',
    'Target closed',
    'Session closed',
    'Connection closed',
    'WebSocket is not open',
    'WebSocket connection closed',
    'Page.navigate timed out',
    'Runtime.addBinding timed out',
    'Target.createTarget timed out',
    'Browser has been closed',
    'Runtime.evaluate timed out',
    'Target.detachFromTarget timed out',  // New in Puppeteer 24.x
    'Target.closeTarget timed out'        // Additional Puppeteer 24.x timeout
  ];
  
  return criticalErrors.some(criticalError => 
    error.message.includes(criticalError)
  );
}

/**
 * Performs comprehensive browser health assessment
 * @param {import('puppeteer').Browser} browserInstance - Puppeteer browser instance
 * @param {object} options - Health check options
 * @returns {Promise<object>} Comprehensive health report
 */
async function performHealthAssessment(browserInstance, options = {}) {
  const {
    timeout = 5000,
    minTimeout = 8000, // Minimum timeout for 24.x stability
    checkMemory = true,
    forceDebug = false
  } = options;

  const assessment = {
    overall: 'unknown',
    timestamp: new Date().toISOString(),
    browser: {},
    memory: {},
    recommendations: [],
    needsRestart: false
  };

  // Auto-adjust timeout based on Puppeteer version
  const versionInfo = detectPuppeteerVersion();
  const adjustedTimeout = versionInfo.needsEnhancedTimeouts ? Math.max(timeout, minTimeout) : timeout;

  if (forceDebug) {
    console.log(formatLogMessage('debug', 'Starting browser health assessment...'));
  }

  // Browser responsiveness check
   assessment.browser = await checkBrowserHealth(browserInstance, adjustedTimeout);
  
  // Memory usage check (if enabled and available)
  if (checkMemory) {
    assessment.memory = await checkBrowserMemory(browserInstance);
  }

  // Combine recommendations
  assessment.recommendations = [
    ...assessment.browser.recommendations,
    ...(assessment.memory.recommendations || [])
  ];

  // Determine overall health and restart necessity
  if (!assessment.browser.healthy) {
    assessment.overall = 'unhealthy';
    assessment.needsRestart = true;
  } else if (assessment.browser.criticalError) {
    assessment.overall = 'critical';
    assessment.needsRestart = true;
  } else if (assessment.recommendations.length > 0) {
    assessment.overall = 'degraded';
    assessment.needsRestart = assessment.recommendations.some(rec => 
      rec.includes('restart required') || 
      rec.includes('High memory usage')
    );
  } else {
    assessment.overall = 'healthy';
    assessment.needsRestart = false;
  }

  if (forceDebug) {
    console.log(formatLogMessage('debug', `Health assessment complete: ${assessment.overall}`));
    if (assessment.recommendations.length > 0) {
      console.log(formatLogMessage('debug', `Recommendations: ${assessment.recommendations.join(', ')}`));
    }
  }

  return assessment;
}

/**
 * Monitors browser health and suggests actions for nwss.js integration
 * @param {import('puppeteer').Browser} browserInstance - Puppeteer browser instance
 * @param {object} context - Context information for logging
 * @param {object} options - Monitoring options
 * @returns {Promise<object>} Monitoring result with action suggestions
 */
async function monitorBrowserHealth(browserInstance, context = {}, options = {}) {
  const {
    siteIndex = 0,
    puppeteerVersion = null, // Allow version override for testing
    totalSites = 0,
    urlsSinceCleanup = 0,
    cleanupInterval = 40,
    forceDebug = false,
    silentMode = false
  } = options;

  const result = {
    shouldRestart: false,
    shouldContinue: true,
    reason: null,
    assessment: null
  };

  try {
    // Use provided version or auto-detect
    const versionInfo = puppeteerVersion || detectPuppeteerVersion();
    const healthTimeout = versionInfo.needsEnhancedTimeouts ? 8000 : 5000;
    // Perform health assessment
    const assessment = await performHealthAssessment(browserInstance, {
      timeout: healthTimeout,
      minTimeout: 8000,
      checkMemory: true,
      forceDebug
    });

    result.assessment = assessment;

    // Decision logic for restart
    if (assessment.browser.criticalError) {
      result.shouldRestart = true;
      result.reason = `Critical protocol error detected - immediate restart required`;
    } else if (assessment.needsRestart) {
      result.shouldRestart = true;
      result.reason = `Browser health: ${assessment.overall} - ${assessment.recommendations[0] || 'restart needed'}`;
    } else if (urlsSinceCleanup >= cleanupInterval) {
      result.shouldRestart = true;
      result.reason = `Scheduled cleanup after ${urlsSinceCleanup} URLs`;
    } else if (assessment.browser.responseTime > 3000) {
      result.shouldRestart = true;
      result.reason = `Slow browser response: ${assessment.browser.responseTime}ms`;
    }

    // Logging
    if (!silentMode && result.shouldRestart) {
      const progress = totalSites > 0 ? ` (${siteIndex + 1}/${totalSites})` : '';
      console.log(`\n${messageColors.fileOp('?? Browser restart needed')} before site${progress}: ${result.reason}`);
    }

    if (forceDebug && !result.shouldRestart) {
      console.log(formatLogMessage('debug', `Browser health OK - continuing (pages: ${assessment.browser.pageCount}, response: ${assessment.browser.responseTime}ms)`));
    }

  } catch (monitorError) {
    result.shouldRestart = true;
    result.reason = `Health monitoring failed: ${monitorError.message}`;
    
    if (forceDebug) {
      console.log(formatLogMessage('debug', `Browser health monitoring error: ${monitorError.message}`));
    }
  }

  return result;
}

/**
 * Simple health check function for quick integration
 * @param {import('puppeteer').Browser} browserInstance - Puppeteer browser instance
 * @returns {Promise<boolean>} True if browser is healthy, false otherwise
 */
async function isBrowserHealthy(browserInstance, timeout = null) {
  const versionInfo = detectPuppeteerVersion();
  const checkTimeout = timeout || (versionInfo.needsEnhancedTimeouts ? 8000 : 3000);
  
  try {
    const health = await checkBrowserHealth(browserInstance, checkTimeout);
    return health.healthy;
  } catch (error) {
    return false;
  }
}

module.exports = {
  detectPuppeteerVersion,
  checkBrowserHealth,
  checkBrowserMemory,
  performHealthAssessment,
  monitorBrowserHealth,
  isBrowserHealthy,
  isCriticalProtocolError
};
