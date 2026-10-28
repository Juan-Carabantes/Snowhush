// Visitors on Windows get its download first and filled in; everyone else gets the Mac's.
if (/Windows/.test(navigator.userAgentData?.platform ?? navigator.userAgent)) {
  for (const downloads of document.querySelectorAll('.downloads')) {
    const [mac, windows] = ['mac', 'windows'].map(platform => downloads.querySelector(`[data-platform="${platform}"]`));
    downloads.prepend(windows);
    windows.classList.remove('secondary');
    mac.classList.add('secondary');
  }
}
