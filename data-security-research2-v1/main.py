from playwright.sync_api import sync_playwright
from lxml import html
import time


def scroll_to_bottom(page, scroll_times=3, sleep_seconds=2):
    """
    模拟滚动到页面底部，每次滚动后休眠指定时间，重复指定次数。
    :param page: Playwright 的 Page 对象
    :param scroll_times: 滚动次数
    :param sleep_seconds: 每次滚动后的休眠时间
    """
    for _ in range(scroll_times):
        page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
        time.sleep(sleep_seconds)


def fetch_page_content(url):
    """
    使用 Playwright 获取指定 URL 的页面内容。
    :param url: 要访问的 URL
    :return: 页面 HTML 内容
    """
    with sync_playwright() as playwright:
        browser = playwright.webkit.launch(headless=True)
        context = browser.new_context()
        page = context.new_page()

        # 访问目标 URL
        page.goto(url)
        page.wait_for_load_state("networkidle")

        # 模拟滚动加载更多内容
        scroll_to_bottom(page)

        # 获取页面 HTML 内容
        page_content = page.content()
        browser.close()
        return page_content


def extract_articles(page_content):
    """
    使用 XPath 从 HTML 中提取文章标题和链接。
    :param page_content: HTML 页面内容
    :return: 标题和链接的列表
    """
    try:
        tree = html.fromstring(page_content)
        titles = tree.xpath('//div/div[1]/div[1]/a/text()')
        links = tree.xpath('//div/div[1]/div[1]/a/@href')
        return [(title.strip(), link.strip()) for title, link in zip(titles, links)]
    except Exception as e:
        print(f"An error occurred while parsing HTML: {e}")
        return []


def display_articles(articles):
    """
    打印文章标题和链接。
    :param articles: 文章的标题和链接列表
    """
    for title, link in articles:
        print(f"{title} - {link}")


def main():
    """
    主函数，串联所有功能。
    """
    url = "https://sectoday.tencent.com/"
    print("Fetching page content...")
    page_content = fetch_page_content(url)
    print("Extracting articles...")
    articles = extract_articles(page_content)
    print("Displaying articles:")
    display_articles(articles)


if __name__ == "__main__":
    main()
