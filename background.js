// 后台脚本，用于处理扩展的后台任务
console.log('敏感信息雷达后台脚本已加载');

chrome.runtime.onInstalled.addListener(() => {
  console.log('敏感信息雷达已安装/更新');
  // 设置默认配置
  chrome.storage.sync.get({
    enableAutoBlock: true,
    alertLevel: 'all', // 'high', 'medium', 'low', 'all'
    enableContext: true,
    // 域名过滤设置
    domainMode: 'include', // 'include' or 'exclude'
    includeDomains: ['wiki.icbc'], // 默认只监控这个域名
    excludeDomains: ['example.com', 'test.com'] // 默认排除这些域名
  }, (defaults) => {
    chrome.storage.sync.set(defaults);
  });
});

// 处理内容脚本的消息
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "getSettings") {
    chrome.storage.sync.get({
      enableAutoBlock: true,
      alertLevel: 'all',
      enableContext: true,
      domainMode: 'include',
      includeDomains: ['wiki.icbc'],
      excludeDomains: ['example.com', 'test.com']
    }, (settings) => {
      sendResponse(settings);
    });
    return true; // 保持消息通道开放
  }
  
  // 检查域名是否应该生效
  if (request.action === "checkDomain") {
    chrome.storage.sync.get({
      domainMode: 'include',
      includeDomains: ['wiki.icbc'],
      excludeDomains: ['example.com', 'test.com']
    }, (settings) => {
      const url = new URL(request.url);
      const hostname = url.hostname.toLowerCase().replace(/^www\./, '');
      let shouldActivate = false;
      
      if (settings.domainMode === 'include') {
        // 包含模式：只在包含列表中的域名生效
        shouldActivate = settings.includeDomains.some(domain => {
          const cleanDomain = domain.toLowerCase().replace(/^www\./, '');
          // 精确匹配或子域名匹配
          return hostname === cleanDomain || 
                 hostname.endsWith('.' + cleanDomain) ||
                 // 处理通配符 *.example.com
                 (cleanDomain.startsWith('*.') && hostname.endsWith(cleanDomain.substring(1)));
        });
      } else {
        // 排除模式：在所有域名生效，除了排除列表
        shouldActivate = !settings.excludeDomains.some(domain => {
          const cleanDomain = domain.toLowerCase().replace(/^www\./, '');
          return hostname === cleanDomain || 
                 hostname.endsWith('.' + cleanDomain) ||
                 (cleanDomain.startsWith('*.') && hostname.endsWith(cleanDomain.substring(1)));
        });
      }
      
      sendResponse({ shouldActivate, settings });
    });
    return true;
  }
  
  // 更新设置
  if (request.action === "updateSettings") {
    chrome.storage.sync.set(request.settings, () => {
      sendResponse({ success: true });
    });
    return true;
  }
  
  return false;
});