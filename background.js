// 后台脚本，用于处理扩展的后台任务
console.log('敏感信息雷达后台脚本已加载');

chrome.runtime.onInstalled.addListener(() => {
  console.log('敏感信息雷达已安装/更新');
  // 设置默认配置
  chrome.storage.sync.get({
    enableAutoBlock: true,
    alertLevel: 'all', // 'high', 'medium', 'low', 'all'
    enableContext: true
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
      enableContext: true
    }, (settings) => {
      sendResponse(settings);
    });
    return true; // 保持消息通道开放
  }
  return false;
});