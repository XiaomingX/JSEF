from playwright.sync_api import sync_playwright
from lxml import html

def fetch_tencent_article():
    # 定义目标 URL
    url = "https://sectoday.tencent.com/api/article/c-IYX5MBW7f1uUFHRJC4/link"

    with sync_playwright() as playwright:
        # 启动无头浏览器
        browser = playwright.webkit.launch(headless=True)
        context = browser.new_context()
        page = context.new_page()

        # 访问目标 URL
        page.goto(url)

        # 等待页面完全加载
        page.wait_for_load_state("networkidle")

        # 获取页面 HTML 内容
        page_content = page.content()
        browser.close()

    # 解析 HTML 并提取内容
    try:
        tree = html.fromstring(page_content)

        # 提取标题和内容
        title = tree.xpath('//*[@id="activity-name"]/text()')
        content = tree.xpath('//*[@id="js_content"]//text()')  # 提取 js_content 中的所有文本内容

        # 打印标题和内容
        print("Title:", title[0].strip() if title else "No Title Found")
        print("Content:", " ".join(content).strip() if content else "No Content Found")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    fetch_tencent_article()
