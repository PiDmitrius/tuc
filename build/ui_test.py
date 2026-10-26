# ui_test.py <base URL>: the owner and issue link scenarios of the pages in
# Chromium; fails on a JavaScript error or a missing step.
import json
import base64
import re
import sys

from playwright.sync_api import expect, sync_playwright

base = sys.argv[1]
errors = []

if len(sys.argv) > 2 and sys.argv[2] == "sealed":
    with sync_playwright() as p:
        browser = p.chromium.launch()
        for suffix in ("/", "/" + "A" * 40 + "#token=" + "a" * 32):
            page = browser.new_page(viewport={"width": 375, "height": 800})
            response = page.goto(base + suffix)
            assert response.status == 503
            expect(page.locator("header")).to_contain_text("ТУЦ")
            expect(page.get_by_role("heading", name="Сервис заблокирован")).to_be_visible()
            expect(page.locator("main")).to_contain_text("tuc unseal")
            expect(page.locator("form")).to_have_count(0)
            expect(page.locator("input")).to_have_count(0)
            page.get_by_role("button", name="Обновить страницу").click()
            page.wait_for_load_state()
            assert page.url == base + suffix
            assert page.evaluate("document.documentElement.scrollWidth <= document.documentElement.clientWidth")
            page.context.close()
        browser.close()
    print("sealed ui ok")
    sys.exit(0)

with sync_playwright() as p:
    # headed, under Xvfb: classic scrollbars, which take room, as on Windows
    browser = p.chromium.launch(headless=False)
    ctx = browser.new_context()
    # The pages are plain HTTP, where copying goes through execCommand: keep
    # what it copies. Choices remembered by an earlier page that it no longer
    # offers start the browser.
    ctx.add_init_script("""
        try { if (localStorage.getItem("tuc-os") === null) for (const k of ["os", "tool", "imp"]) localStorage.setItem("tuc-" + k, "stale"); } catch {}
        const exec = document.execCommand.bind(document);
        document.execCommand = c => { if (c === "copy") window.copied = document.activeElement.value; return exec(c); };
    """)
    page = ctx.new_page()
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.on("console", lambda m: m.type == "error" and "Failed to load resource" not in m.text and errors.append(m.text))

    # Create a root CA with the filled in data
    page.goto(base + "/")
    expect(page.get_by_text("Открытых УЦ пока нет", exact=True)).to_be_visible()
    expect(page.locator("#root")).to_be_hidden()
    page.locator("#create-root > .head").click()
    expect(page.locator("#root")).to_be_visible()
    expect(page.locator("input[name=subject]")).to_have_value(re.compile(r"^CN=Тестовый УЦ \(уровень 1\) \(\d{4}\.\d{2}\.\d{2} \d{2}:\d{2}:\d{2} UTC\)"))
    page.get_by_label("Алгоритм ключа").select_option("ecdsa384")
    page.get_by_role("button", name="Создать УЦ").click()
    page.wait_for_url(re.compile(r"/[0-9A-F]{40}#token=[a-z2-7]{32}$"))
    expect(page.locator(".title .b", has_text="ECDSA P-384")).to_be_visible()
    admin_url = page.url
    expect(page.get_by_text("Сохраните ссылку управления.")).to_be_visible()
    page.get_by_role("button", name="Скопировать ссылку управления").click()
    assert page.evaluate("window.copied") == admin_url
    page.get_by_role("button", name="Ссылка сохранена").click()
    expect(page.locator("#access-pill")).to_have_text("Ссылка сохранена")
    expect(page.locator("#save")).to_be_hidden()
    # The owner sees every row closed, a summary on each
    expect(page.locator(".item.open")).to_have_count(0)
    expect(page.locator("#issue-meta")).to_have_text("PFX")
    expect(page.locator("#hier-row .meta")).to_have_text("уровень 1 · подчинённых УЦ: 0")

    # The enroll command follows the choices
    issue_card = page.locator("#issue")
    page.locator("#issue .head").click()
    tools = issue_card.get_by_role("radiogroup", name="Способ выпуска")
    expect(issue_card.locator("input[name=tool][value=pfx]")).to_be_checked()
    expect(page.locator("#os-seg")).to_be_hidden()
    tools.get_by_text("КриптоПро", exact=True).click()
    page.locator("#os-seg").get_by_text("Linux", exact=True).click()
    issue_card.get_by_text("Без цепочки").click()
    page.get_by_role("button", name="Скопировать команду").click()
    cmd = page.evaluate("window.copied")
    assert '-ca "$TUC/justcert" -silent' in cmd and "TUC=" + base in cmd, cmd
    # A client needs no DNS name; a server does, and both take it
    issue_card.get_by_text("TLS-клиент", exact=True).click()
    expect(page.locator("#fqdn-label")).to_have_text("DNS-имя (необязательно)")
    page.get_by_role("button", name="Скопировать команду").click()
    cmd = page.evaluate("window.copied")
    assert '-ca "$TUC/tls-client/justcert" -silent' in cmd and "-altname" not in cmd, cmd
    issue_card.get_by_text("TLS-сервер", exact=True).click()
    page.get_by_role("button", name="Скопировать команду").click()
    expect(page.locator("#enroll-status")).to_have_text("Укажите DNS-имя")
    expect(page.locator("#fqdn")).to_be_focused()
    page.locator("#fqdn").fill("srv.example.org")
    page.get_by_role("button", name="Скопировать команду").click()
    cmd = page.evaluate("window.copied")
    assert "FQDN=srv.example.org" in cmd and "-eku" not in cmd and '-ca "$TUC/tls-server/tls-client/justcert"' in cmd, cmd
    tools.get_by_text("OpenSSL", exact=True).click()
    page.get_by_role("button", name="Скопировать команду").click()
    cmd = page.evaluate("window.copied")
    assert '"$EST+tls-server+tls-client/simpleenroll"' in cmd and "subjectAltName=DNS:$FQDN" in cmd and "extendedKeyUsage" not in cmd, cmd
    tools.get_by_text("КриптоПро", exact=True).click()
    page.locator("#issued > .head").click()
    expect(page.get_by_text("Сертификатов пока нет.")).to_be_visible()
    expect(page.locator("#issued-meta")).to_have_text("0")

    # Close issuance: the command and the issue link carry the issue token
    page.locator("#settings .head").click()
    page.locator("#mode").get_by_text("По ссылке").click()
    expect(page.locator("#mode-pill")).to_have_text("Выпуск по ссылке")
    issue_card.get_by_text("TLS-сервер", exact=True).click()
    issue_card.get_by_text("TLS-клиент", exact=True).click()
    page.get_by_role("button", name="Скопировать команду").click()
    cmd = page.evaluate("window.copied")
    assert re.search(r"TUC=\S+/[0-9A-F]{40}/[a-z2-7]{32} && \\\n", cmd), cmd
    tools.get_by_text("OpenSSL", exact=True).click()
    expect(page.locator("#os-seg")).to_be_hidden()
    page.get_by_role("button", name="Скопировать команду").click()
    cmd = page.evaluate("window.copied")
    assert re.search(r"EST=http://tuc:[a-z2-7]{32}@\S+/\.well-known/est/[0-9A-F]{40} && \\\n", cmd) and "-newkey ec" in cmd, cmd
    # A PFX made by the CA downloads under the name shown
    tools.get_by_text("PFX", exact=True).click()
    expect(page.locator("#copy-enroll")).to_be_hidden()
    expect(page.locator("#pfx-algo")).to_have_value("ecdsa384")
    # The name of a TLS PFX starts with the DNS name while the CN fits
    issue_card.get_by_text("TLS-сервер", exact=True).click()
    page.locator("#fqdn").fill("service.integration.testing.development.example.org")
    expect(page.locator("#pfx-name")).to_have_value(re.compile(r"^TUC-\d{8}-\d{6}$"))
    page.locator("#fqdn").fill("srv.example.org")
    expect(page.locator("#pfx-name")).to_have_value(re.compile(r"^srv\.example\.org-TUC-\d{8}-\d{6}$"))
    issue_card.get_by_text("TLS-сервер", exact=True).click()
    # An existing PFX: its import commands take the base64, CN and password typed
    expect(page.locator("#pfx-import")).to_be_hidden()
    page.get_by_role("button", name="Импорт имеющегося PFX").click()
    page.get_by_role("button", name="Скопировать команду импорта").click()
    expect(page.locator("#imp-b64")).to_be_focused()
    page.locator("#imp-b64").fill("QUJD\nREVG"); page.locator("#imp-pass").fill("it's")
    page.get_by_role("button", name="Скопировать команду импорта").click()
    cmd = page.evaluate("window.copied")
    assert re.search(r"NAME='TUC-\d{8}-\d{6}' && \\\nPASS='it'\\''s' && \\\n", cmd) and "printf %s 'QUJDREVG'" in cmd, cmd
    password = page.locator("#pfx-password").input_value()
    assert re.fullmatch(r"TUC-\d{8}-\d{6}", page.locator("#pfx-name").input_value()) and len(password) == 12, password
    # The PFX issued in the browser: its base64, its file and its password
    page.get_by_role("button", name="Выпустить PFX").click()
    expect(page.locator("#enroll-status")).to_have_text("PFX выпущен")
    encoded = page.locator("#pfx-b64").input_value()
    expect(page.locator("#pfx-pass-out")).to_have_value(password)
    with page.expect_download() as d:
        page.locator("#pfx-file").click()
    name = d.value.suggested_filename.removesuffix(".pfx")
    assert re.fullmatch(r"TUC-\d{8}-\d{6}", name), name
    assert d.value.path().read_bytes() == base64.b64decode(encoded)
    # Import and revoke commands carry the PFX issued; the form gets a new password
    expect(page.locator("#os3-seg")).to_be_hidden()
    expect(page.locator("#imp-b64")).to_have_value(encoded)
    expect(page.locator("#imp-fields")).to_be_hidden()
    assert page.locator("#pfx-password").input_value() != password
    page.get_by_role("button", name="Скопировать команду импорта").click()
    cmd = page.evaluate("window.copied")
    assert "NAME='" + name + "' && \\\nPASS='" + password + "' && \\\n" in cmd and "-nocerts -nodes" in cmd and encoded in cmd, cmd
    page.locator("#revoke .head").click()
    page.get_by_role("button", name="Скопировать команду отзыва").click()
    cmd = page.evaluate("window.copied")
    assert "PASS='" + password + "'" in cmd and encoded in cmd and not re.search(r"/[0-9A-F]{40}/[a-z2-7]{32}", cmd), cmd
    page.locator("#pfx-import").get_by_text("КриптоПро", exact=True).click()
    page.locator("#os3-seg").get_by_text("Linux", exact=True).click()
    page.get_by_role("button", name="Скопировать команду импорта").click()
    cmd = page.evaluate("window.copied")
    assert "certmgr -inst -pfx" in cmd and re.search(r"/[0-9A-F]{40}\.crt", cmd), cmd
    # a CN with a space: the file is named without it; CryptoPro finds the certificate by thumbprint
    page.locator("#pfx-name").fill("Test User")
    page.get_by_role("button", name="Выпустить PFX").click()
    expect(page.locator("#pfx-file")).to_have_attribute("download", "Test_User.pfx")
    page.get_by_role("button", name="Скопировать команду импорта").click()
    cmd = page.evaluate("window.copied")
    assert "SHA1=$(awk" in cmd and "PrivateKey Link" in cmd and "NAME=" not in cmd, cmd
    # Issued and installed by a command: over the page address, with the issue link
    dests = issue_card.get_by_role("radiogroup", name="Куда")
    dests.get_by_text("OpenSSL", exact=True).click()
    expect(page.locator("#get-pfx")).to_be_hidden()
    page.locator("#copy-enroll").click()
    cmd = page.evaluate("window.copied")
    assert re.search(r"TUC=" + re.escape(base) + r"/[0-9A-F]{40}/[a-z2-7]{32} && ", cmd) and "--data-binary '{" in cmd and '"$TUC/pfx"' in cmd, cmd
    expect(page.locator("#enroll-note")).to_contain_text("Команда содержит ссылку выпуска")
    expect(page.locator("#revoke input[name=tool2][value=openssl]")).to_be_checked()
    dests.get_by_text("КриптоПро", exact=True).click()
    page.locator("#os-seg").get_by_text("Windows", exact=True).click()
    page.locator("#copy-enroll").click()
    cmd = page.evaluate("window.copied")
    assert "FromBase64String(" in cmd and "curl.exe" in cmd and "Remove-Item" in cmd, cmd
    good_password = page.locator("#pfx-password").input_value()
    page.locator("#pfx-password").fill('ab"cd')
    page.locator("#copy-enroll").click()
    expect(page.locator("#enroll-status")).to_have_text('Для команды Windows пароль без " и без \\ в конце')
    page.locator("#pfx-password").fill(good_password)
    page.locator("#os-seg").get_by_text("Linux", exact=True).click()
    dests.get_by_text("Браузер", exact=True).click()
    page.locator("#pfx-import").get_by_text("OpenSSL", exact=True).click()
    page.locator("#pfx-import").get_by_text("КриптоПро", exact=True).click()
    # The check and the revoke follow where the PFX is imported
    expect(page.locator("#revoke input[name=tool2][value=cryptopro]")).to_be_checked()
    expect(page.locator("#verify input[name=where][value=cryptopro]")).to_be_checked()
    page.locator("#pfx-import").get_by_text("OpenSSL", exact=True).click()
    expect(page.locator("#revoke input[name=tool2][value=pfx]")).to_be_checked()
    expect(page.locator("#rev-b64")).to_be_visible()
    expect(page.locator("#rev-b64")).not_to_have_value("")
    page.locator("#verify .head").click()
    expect(page.locator("#verify input[name=where][value=openssl]")).to_be_checked()
    page.get_by_role("button", name="Скопировать команду проверки").click()
    assert "openssl verify -crl_download -crl_check_all -CRLfile" in page.evaluate("window.copied")
    # back on the page, an existing PFX goes where the import was chosen last
    page.locator("#pfx-import").get_by_text("КриптоПро", exact=True).click()
    page.reload()
    page.locator("#issue > .head").click()
    page.get_by_role("button", name="Импорт имеющегося PFX").click()
    expect(page.locator("#verify input[name=where][value=cryptopro]")).to_be_checked()
    expect(page.locator("#revoke input[name=tool2][value=cryptopro]")).to_be_checked()
    page.locator("#pfx-import").get_by_text("OpenSSL", exact=True).click()
    for row in ["#revoke", "#settings"]:
        page.locator(row + " .head").click()
    # Where the key is, chosen in the revoke block, leaves the issue as it is
    page.locator("#revoke").get_by_text("В КриптоПро", exact=True).click()
    expect(issue_card.locator("input[name=tool][value=pfx]")).to_be_checked()
    tools.get_by_text("КриптоПро", exact=True).click()
    expect(page.locator("#copy-enroll")).to_be_visible()
    page.locator("#os-seg").get_by_text("Linux", exact=True).click()
    expect(page.locator("#issue-meta")).to_have_text("КриптоПро")
    page.locator("#access .head").click()
    page.get_by_role("button", name="Скопировать ссылку выпуска").click()
    issue_link = page.evaluate("window.copied")
    assert re.search(r"#issue=[a-z2-7]{32}$", issue_link) and page.locator("#issue-link").input_value() == issue_link, issue_link

    # Creating an intermediate CA is a row; a bad name is told at its field
    page.locator("#child-row .head").click()
    expect(page.locator("#child input[name=mode][value=closed]")).to_be_checked()
    page.locator("#child input[name=subject]").fill("CN=x,C=Россия")
    page.locator("#child").get_by_role("button", name="Создать подчинённый УЦ").click()
    expect(page.locator("#child-subject-error")).to_have_text("Недопустимые символы в значении атрибута C")
    expect(page.locator("#child [role=status]")).to_have_text("Не удалось создать УЦ")
    page.locator("#child-row .head").click()

    # Issuance: CRL and OCSP for a year by default, saved and shown again
    f = page.locator("#issuance")
    expect(f.locator("input[name=crl]")).to_be_checked()
    expect(f.locator("input[name=ocsp]")).to_be_checked()
    expect(f.locator("input[name=from]")).to_have_value("0")
    expect(f.locator("input[name=days]")).to_have_value("365")
    f.get_by_label("OCSP — адрес службы проверки отзыва (AIA)").uncheck()
    f.locator("input[name=from]").fill("-10")
    f.locator("input[name=days]").fill("5")
    f.get_by_role("button", name="Сохранить").click()
    expect(page.locator("#issuance-status")).to_have_text("Сохранено")
    page.reload()
    page.locator("#settings .head").click()
    expect(f.locator("input[name=crl]")).to_be_checked()
    expect(f.locator("input[name=ocsp]")).not_to_be_checked()
    expect(f.locator("input[name=from]")).to_have_value("-10")
    f.locator("input[name=from]").fill("0")
    f.locator("input[name=days]").fill("365")
    f.get_by_role("button", name="Сохранить").click()
    expect(page.locator("#issuance-status")).to_have_text("Сохранено")

    # An intermediate revokes itself at its issuer
    page.locator("#child-row .head").click()
    page.locator("#child").get_by_role("button", name="Создать подчинённый УЦ").click()
    page.wait_for_url(lambda u: u != admin_url and re.search(r"/[0-9A-F]{40}#token=[a-z2-7]{32}$", u))
    page.locator("#settings .head").click()
    page.get_by_role("button", name="Отозвать УЦ").click()
    page.get_by_role("button", name="Отозвать безвозвратно").click()
    expect(page.locator(".title .b.red")).to_contain_text("Отозван")
    page.goto(admin_url)
    page.reload()
    page.locator("#settings .head").click()

    # An intermediate CA of another algorithm, opened with its own admin link
    page.locator("#child-row .head").click()
    expect(page.locator("#child input[name=subject]")).to_have_value(re.compile(r"^CN=Тестовый УЦ \(уровень 2\) \(\d{4}\.\d{2}\.\d{2} \d{2}:\d{2}:\d{2} UTC\)"))
    expect(page.locator("#child select[name=algo]")).to_have_value("ecdsa384")
    page.locator("#child select[name=algo]").select_option("gost512")
    page.locator("#child").get_by_role("button", name="Создать подчинённый УЦ").click()
    page.wait_for_url(lambda u: u != admin_url and re.search(r"/[0-9A-F]{40}#token=[a-z2-7]{32}$", u))
    expect(page.locator(".title .b", has_text="ГОСТ 512")).to_be_visible()
    inter_url = page.url
    expect(page.locator(".position .kind")).to_have_text("Подчинённый УЦ · уровень 2")
    expect(page.get_by_role("link", name="Родительский УЦ", exact=True)).to_be_visible()
    expect(page.locator("#hier-row .meta")).to_have_text("уровень 2 · подчинённых УЦ: 0")
    expect(page.locator("#hier li")).to_have_count(2)
    expect(page.locator("#hier li[aria-current=page]")).to_contain_text("Тестовый УЦ (уровень 2)")
    # Tokens are local to each CA; hierarchy navigation is public.
    expect(page.locator(".position > a")).to_have_attribute("href", re.compile(r"/[0-9A-F]{40}$"))
    page.goto(inter_url.split("#")[0] + "#" + admin_url.split("#")[1])
    expect(page.locator("#access-error")).to_contain_text("Ссылка управления не подходит")
    expect(page.locator("#management-rows")).to_be_hidden()
    page.goto(inter_url)
    page.locator("#access > .head").click()
    expect(page.locator("#admin-link")).to_have_value(inter_url)

    # The root lists the intermediates and the PFX leaves, finds an intermediate, revokes it
    page.goto(admin_url)
    page.reload()
    page.locator("#issued > .head").click()
    row = page.locator("#certs .item")
    expect(row).to_have_count(4)
    # Hierarchy links carry no management token
    expect(page.locator("#hier a.child")).to_have_count(2)
    expect(page.locator("#hier a.child").first).to_have_attribute("href", re.compile(r"^/[0-9A-F]{40}$"))
    page.locator("#q").fill(inter_url.split("/")[-1].split("#")[0][:10].lower())
    page.get_by_role("button", name="Найти").click()
    expect(row).to_have_count(1)
    expect(row.get_by_role("link", name="Управлять")).to_have_count(0)
    expect(row.locator("a.name")).to_have_attribute("href", re.compile(r"^/[0-9A-F]{40}$"))
    row.locator(".head").click()
    row.get_by_role("button", name="Отозвать", exact=True).click()
    row.get_by_role("button", name="Отозвать сертификат").click()
    expect(row.locator(".head .b.red")).to_have_text("Отозван")
    expect(page.locator("#hier li", has_text=inter_url.split("/")[-1].split("#")[0][:8]).locator(".b.red")).to_have_count(1)

    # The issue link of the closed root shows the command with the token
    tp = ctx.new_page()
    tp.on("pageerror", lambda e: errors.append(str(e)))
    tp.goto(issue_link)
    expect(tp.locator("#pill-issue")).to_be_visible()
    expect(tp.locator("#settings")).to_be_hidden()
    tp.get_by_role("button", name="Скопировать команду").click()
    assert issue_link.split("#issue=")[1] in tp.evaluate("window.copied")

    # A visitor of the closed root: no command, one line instead
    tp.goto(admin_url.split("#")[0])
    expect(tp.locator("#issue-meta")).to_have_text("по ссылке")
    tp.locator("#issue > .head").click()
    expect(tp.locator("#closed-note")).to_be_visible()
    expect(tp.locator("#issue-form")).to_be_hidden()

    # A wrong admin token keeps the public page
    tp.goto(admin_url.split("#")[0] + "#token=" + "a" * 32)
    expect(tp.get_by_text("Ссылка управления не подходит к этому УЦ.")).to_be_visible()
    expect(tp.locator("#settings")).to_be_hidden()

    # The intermediate the root revoked says so and has nothing more to revoke
    page.goto(inter_url)
    page.reload()
    expect(page.locator(".title .b.red")).to_contain_text("Отозван")
    page.locator("#settings .head").click()
    expect(page.get_by_role("button", name="Отозвать УЦ")).to_have_count(0)

    # The last level the hierarchy allows: its owner page works without the
    # form of a child
    tok, last = admin_url.split("#token=")[1], admin_url.split("#")[0].split("/")[-1]
    for _ in range(7):
        reply = ctx.request.post(base + "/" + last + "/new", headers={"Content-Type": "application/json"}, data=json.dumps({"token": tok, "subject": "CN=deep"})).json()
        last, tok = reply["id"], reply["admin"]
    dp = ctx.new_page()
    dp.on("pageerror", lambda e: errors.append(str(e)))
    dp.goto(base + "/" + last + "#token=" + tok)
    dp.locator("#issued > .head").click()
    expect(dp.locator("#issued-meta")).to_have_text("0")
    expect(dp.locator("#child-row")).to_have_count(0)
    dp.close()

    # Every kind of page keeps the header in place, loads without shifting
    # and fits a phone
    sp = browser.new_page(viewport={"width": 1280, "height": 800})
    sp.add_init_script("""window.shift = 0; new PerformanceObserver(l => { for (const e of l.getEntries()) if (!e.hadRecentInput) window.shift += e.value; })
        .observe({type: "layout-shift", buffered: true});""")
    bar = lambda: sp.locator("header").bounding_box()
    want, title_y = None, None
    for url in [base + "/", admin_url.split("#")[0], admin_url, issue_link, inter_url.split("#")[0], inter_url, base + "/" + "A" * 40,
                base + "/" + "A" * 40 + "#token=" + "a" * 32, base + "/#issue=" + "a" * 32]:
        sp.goto("about:blank")
        sp.goto(url)
        sp.wait_for_timeout(700)
        assert sp.evaluate("getComputedStyle(document.querySelector('main')).visibility") == "visible", ("hidden page", url)
        if sp.locator(".title").count():
            title_y = title_y or sp.locator(".title").bounding_box()["y"]
            assert sp.locator(".title").bounding_box()["y"] == title_y, ("CA name moved", url)
        want = want or bar()
        assert bar() == want, (url, bar(), want)
        assert sp.evaluate("window.shift") == 0, (url, sp.evaluate("window.shift"))
    sp.goto("about:blank")
    sp.goto(admin_url)
    for item in ["#cert", "#revoke", "#settings"]:
        sp.locator(item + " .head").click()
    # a click opens a row without focusing its head: no focus ring
    expect(sp.locator("#settings .head")).not_to_be_focused()
    sp.evaluate("scrollTo(0, 0)")
    assert bar() == want, ("open rows", bar(), want)
    # switching the mode keeps the badges where they are, even at 320 px
    sp.set_viewport_size({"width": 320, "height": 800})
    title = lambda: sp.locator(".title").bounding_box()["height"]
    before = title()
    sp.evaluate("setMode(!admin.closed)")
    assert title() == before, ("mode badge moved the title", before, title())
    sp.evaluate("setMode(admin.closed)")
    sp.set_viewport_size({"width": 375, "height": 800})
    for url in [base + "/", admin_url]:
        sp.goto("about:blank")
        sp.goto(url)
        sp.wait_for_timeout(500)
        assert sp.evaluate("document.documentElement.scrollWidth <= document.documentElement.clientWidth"), ("overflow at 375 px", url)
    sp.close()

    # A script error of the page, here without storage, leaves the owner page
    # shown with a message instead of blank
    ep = ctx.new_page()
    ep.add_init_script("Object.defineProperty(window, 'localStorage', {value: undefined})")
    ep.goto(admin_url)
    expect(ep.locator("#access-error")).to_contain_text("Страница загрузилась не полностью: ")
    # an error of a script from elsewhere, such as a browser extension, is not the page's
    fp = ctx.new_page()
    fp.goto(admin_url)
    fp.evaluate("dispatchEvent(new ErrorEvent('error', {message: 'x', filename: 'chrome-extension://e/content.js'}))")
    fp.evaluate("const r = Promise.reject(Object.assign(new Error('y'), {stack: 'Error: y\\n at chrome-extension://e/content.js:1:1'})); 0")
    fp.wait_for_timeout(300)
    expect(fp.locator("#access-error")).to_be_hidden()
    fp.close()
    expect(ep.locator(".title h2")).to_be_visible()
    ep.close()

    # Disable the intermediate: its certificate answers 503 and every visitor
    # sees it; enable it back. The page has no way to delete a CA.
    expect(page.get_by_role("button", name="Уничтожить УЦ")).to_have_count(0)
    if not page.locator("#settings.open").count():
        page.locator("#settings .head").click()
    page.get_by_role("button", name="Отключить УЦ").click()
    expect(page.locator("#disabled-status")).to_have_text("УЦ отключён")
    expect(page.locator("#disabled-pill")).to_be_visible()
    crt = inter_url.split("#")[0] + ".crt"
    assert page.request.get(crt).status == 503
    page.reload()
    expect(page.locator("#disabled-pill")).to_be_visible()
    if not page.locator("#settings.open").count():
        page.locator("#settings .head").click()
    page.get_by_role("button", name="Включить УЦ").click()
    expect(page.locator("#disabled-pill")).to_be_hidden()
    assert page.request.get(crt).status == 200

    # Each audience starts without preferences or access flags from another visit.
    def fresh(url):
        context = browser.new_context()
        context.add_init_script("""
            const exec = document.execCommand.bind(document);
            document.execCommand = c => { if (c === 'copy') window.copied = document.activeElement.value; return exec(c); };
        """)
        tab = context.new_page()
        tab.on("pageerror", lambda error: errors.append(str(error)))
        tab.goto(url)
        return tab

    creator = fresh(base + "/")
    expect(creator.locator("#public-cas a").first).to_be_visible()
    # the list shows what the service sets, never a name a user chose
    assert "Тестовый УЦ" not in creator.locator("#public-cas").inner_text()
    for link in creator.locator("#public-cas a").all():
        assert re.fullmatch(r"/[0-9A-F]{40}", link.get_attribute("href"))
        expect(link.locator(".meta")).to_have_text(re.compile(r"\d{4}\.\d{2}\.\d{2} \d{2}:\d{2}:\d{2} UTC"))
    first_url = creator.locator("#public-cas a").first.get_attribute("href")
    creator.locator("#public-cas a").first.click()
    creator.wait_for_url(base + first_url)
    creator.goto(base + "/")
    expect(creator.locator("#root")).to_be_hidden()
    creator.locator("#create-root > .head").click()
    creator.get_by_label("Алгоритм ключа").select_option("ecdsa256")
    creator.get_by_role("button", name="Создать УЦ").click()
    creator.wait_for_url(re.compile(r"/[0-9A-F]{40}#token="))
    public_url = creator.url.split("#")[0]
    visitor = fresh(public_url)
    recipient = fresh(issue_link)
    owner = fresh(admin_url)
    expect(visitor.locator("#issue.open")).to_have_count(0)
    visitor.locator("#issue > .head").click()
    for tab in (visitor, recipient):
        expect(tab.locator("#issue.open")).to_be_visible()
        expect(tab.locator("input[name=tool][value=pfx]")).to_be_checked()
        expect(tab.locator("#tls-server")).not_to_be_checked()
        expect(tab.locator("#tls-client")).not_to_be_checked()
        expect(tab.locator("#settings")).to_be_hidden()
        tab.locator("#get-pfx").click()
        expect(tab.locator("#enroll-status")).to_have_text("PFX выпущен")
        assert len(tab.locator("#pfx-b64").input_value()) > 1000
        expect(tab.locator("#pfx-import")).to_be_visible()
        tab.locator("#copy-import").click()
        assert tab.locator("#pfx-b64").input_value() in tab.evaluate("window.copied")
    expect(recipient.locator("#pill-issue")).to_be_visible()
    expect(owner.locator("#pill-admin")).to_be_visible()
    expect(owner.locator(".item.open")).to_have_count(0)
    expect(owner.locator("#save")).to_be_visible()
    owner.locator("#issue > .head").click()
    owner.locator("input[name=tool][value=cryptopro]").locator("..").click()
    owner.locator("#os-seg").get_by_text("Linux", exact=True).click()
    owner.locator("#issue").get_by_text("Без цепочки", exact=True).click()
    owner.locator("#issue").get_by_text("TLS-сервер", exact=True).click()
    for invalid_dns in ("a" * 64 + ".test", ".".join(["a" * 63] * 4), "a.test.", "*.test"):
        owner.locator("#fqdn").fill(invalid_dns)
        owner.locator("#copy-enroll").click()
        expect(owner.locator("#enroll-status")).to_have_text("Некорректное DNS-имя")
        expect(owner.locator("#fqdn")).to_be_focused()
    owner.locator("#fqdn").fill("srv.example.org")
    owner.locator("#copy-enroll").click()
    command = owner.evaluate("window.copied")
    assert "FQDN=srv.example.org" in command and '/justcert" -silent' in command
    owner.reload()
    owner.locator("#issue > .head").click()
    expect(owner.locator("input[name=tool][value=cryptopro]")).to_be_checked()
    expect(owner.locator("#tls-server")).not_to_be_checked()
    expect(owner.locator("input[name=response][value=chain]")).to_be_checked()
    owner.locator("#issue").get_by_text("PFX", exact=True).click()
    owner.locator("#pfx-algo").select_option("rsa2048")
    owner.locator("#pfx-name").fill("UX User")
    saved_password = owner.locator("#pfx-password").input_value()
    owner.locator("#get-pfx").click()
    expect(owner.locator("#pfx-file")).to_have_attribute("download", "UX_User.pfx")
    owner.locator("#copy-import").click()
    command = owner.evaluate("window.copied")
    assert saved_password in command and ("NAME='UX_User'" in command or "SHA1=" in command), command
    owner.locator("#saved").click()
    owner.reload()
    expect(owner.locator("#save")).to_be_hidden()
    owner.locator("#issue > .head").click()
    owner.locator("#open-import").click()
    expect(owner.locator("#imp-fields")).to_be_visible()
    expect(owner.locator("#imp-b64")).to_have_value("")
    expect(owner.locator("#pfx-result")).to_be_hidden()
    expect(owner.locator("#imp-pass")).to_have_value("")
    for tab in (creator, visitor, recipient, owner):
        tab.context.close()
    # A non-GOST issuer still needs the engine for its GOST ancestor.
    probe = browser.new_page()
    def json_post(path, data):
        response = probe.request.post(base + path, headers={"Content-Type": "application/json"}, data=json.dumps(data))
        assert response.ok, response.text()
        return response.json()
    root = json_post("/new", {"subject": "CN=GOST root", "algo": "gost256"})
    child = json_post("/" + root["id"] + "/new", {"subject": "CN=RSA child", "algo": "rsa2048", "token": root["admin"]})
    probe.goto(base + "/" + child["id"])
    if "open" not in probe.locator("#issue").get_attribute("class").split():
        probe.locator("#issue > .head").click()
    probe.locator('input[name=tool][value=openssl]').locator('..').click()
    expect(probe.locator("#enroll-note")).to_contain_text("OpenSSL с gost-engine")
    if "open" not in probe.locator("#verify").get_attribute("class").split():
        probe.locator("#verify > .head").click()
    probe.locator('input[name=where][value=openssl]').locator('..').click()
    expect(probe.locator("#verify-note")).to_contain_text("OpenSSL с gost-engine")
    probe.locator('input[name=tool][value=pfx]').locator('..').click()
    probe.locator("#pfx-algo").select_option("rsa2048")
    probe.locator("#get-pfx").click()
    expect(probe.locator("#enroll-status")).to_have_text("PFX выпущен")
    probe.locator('input[name=imp][value=openssl]').locator('..').click()
    expect(probe.locator("#import-note")).to_contain_text("Нужен OpenSSL с gost-engine")
    expect(probe.locator("#management-rows")).to_be_hidden()
    assert probe.locator("#public-rows > .item").evaluate_all("rows => rows.map(r => r.id)") == ["issue", "verify", "revoke", "cert", "hier-row"]
    probe.goto(base + "/" + child["id"] + "#token=" + child["admin"])
    expect(probe.locator("#management-rows")).to_be_visible()
    assert probe.locator("#management-rows > .item").evaluate_all("rows => rows.map(r => r.id)") == ["issued", "child-row", "access", "settings"]
    expect(probe.locator("#issue-term")).to_have_text("срок 365 дней")
    probe.locator("#issue-settings").click()
    expect(probe.locator("#issuance input[name=days]")).to_be_focused()
    probe.locator("#issuance input[name=days]").fill("1")
    probe.locator("#issuance").get_by_role("button", name="Сохранить", exact=True).click()
    expect(probe.locator("#issue-term")).to_have_text("срок 1 день")
    probe.locator("#issuance input[name=from]").fill("-3")
    probe.locator("#issuance input[name=days]").fill("30")
    probe.locator("#issuance").get_by_role("button", name="Сохранить", exact=True).click()
    expect(probe.locator("#issue-term")).to_have_text("срок 30 дней, начало -3 дн. от выпуска")
    probe.locator("#access > .head").click()
    old_issue = probe.locator("#issue-link").input_value().split("#issue=")[1]
    probe.locator("#rotate-issue").click()
    expect(probe.locator("#issue-link")).not_to_have_value(re.compile(re.escape(old_issue)))
    response = probe.request.post(base + "/" + child["id"] + "/" + old_issue + "/pfx", headers={"Content-Type": "application/json"}, data=json.dumps({"name": "old", "password": "test"}))
    assert response.status == 403
    old_admin = child["admin"]
    probe.locator("#rotate-admin").click()
    expect(probe.locator("#admin-link")).not_to_have_value(re.compile(re.escape(old_admin)))
    expect(probe.locator("#save")).to_be_visible()
    assert probe.url == probe.locator("#admin-link").input_value()
    response = probe.request.post(base + "/" + child["id"] + "/admin", headers={"Content-Type": "application/json"}, data=json.dumps({"token": old_admin}))
    assert response.status == 403
    parent_link = probe.url
    probe.locator("#saved").click()
    probe.locator("#child-row > .head").click()
    probe.locator("#child").get_by_role("button", name="Создать подчинённый УЦ", exact=True).click()
    probe.wait_for_url(lambda url: url != parent_link and "#token=" in url)
    expect(probe.locator("#save")).to_be_visible()
    probe.goto(parent_link)
    probe.reload()
    expect(probe.locator("#save")).to_be_hidden()
    expect(probe.locator("#management-rows")).to_be_visible()
    probe.context.close()
    browser.close()

if errors:
    sys.exit("JavaScript errors: " + "; ".join(errors))
print("ui ok")
