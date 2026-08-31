import pytest
from people.analytics_miner import (
    extract_analytics_ids,
    correlate_shared_analytics,
)


def test_extract_analytics_ids_from_html():
    sample_html = """
    <html>
    <head>
        <!-- Google Tag Manager -->
        <script>(function(w,d,s,l,i){w[l]=w[l]||[];w[l].push({'gtm.start':
        new Date().getTime(),event:'gtm.js'});var f=d.getElementsByTagName(s)[0],
        j=d.createElement(s),dl=l!='dataLayer'?'&l='+l:'';j.async=true;j.src=
        'https://www.googletagmanager.com/gtm.js?id='+i+dl;f.parentNode.insertBefore(j,f);
        })(window,document,'script','dataLayer','GTM-NW8XYZ4');</script>
        <!-- End Google Tag Manager -->
        
        <!-- Google Analytics 4 -->
        <script async src="https://www.googletagmanager.com/gtag/js?id=G-1234567890"></script>
        
        <!-- Google AdSense -->
        <script data-ad-client="ca-pub-1234567890123456" async src="https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js"></script>
    </head>
    <body>
        <h1>Corporate Portal</h1>
    </body>
    </html>
    """

    tokens = extract_analytics_ids(sample_html)
    assert "GTM-NW8XYZ4" in tokens.get("gtm", set())
    assert "G-1234567890" in tokens.get("ga4", set())
    assert "pub-1234567890123456" in tokens.get("adsense", set())


def test_correlate_shared_analytics_boost():
    parent_tokens = {
        "gtm": {"GTM-CORP123"},
        "ga4": {"G-ABC12345"},
    }
    cand_tokens_match = {
        "gtm": {"GTM-CORP123"},
        "ga4": {"G-XYZ99999"},
    }
    cand_tokens_no_match = {
        "gtm": {"GTM-OTHER99"},
    }

    has_shared, boost, anchors = correlate_shared_analytics(parent_tokens, cand_tokens_match)
    assert has_shared is True
    assert boost >= 45
    assert len(anchors) == 1
    assert "GTM-CORP123" in anchors[0]["description"]

    has_shared_none, boost_none, anchors_none = correlate_shared_analytics(parent_tokens, cand_tokens_no_match)
    assert has_shared_none is False
    assert boost_none == 0
    assert len(anchors_none) == 0
