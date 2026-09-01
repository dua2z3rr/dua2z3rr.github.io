# frozen_string_literal: true

# Generates SCOPED category pages for each parent -> child pair, i.e. posts whose
# categories[0] == parent AND categories[1] == child.
#
# URL: /categories/<parent-slug>-<child-slug>/   (single path segment on purpose)
# These back the sub-category links on the Categories (Topics) page so that, e.g.,
# "CTF Competitions -> Challenges" lists only the CTF challenge posts instead of the
# global /categories/challenges/ page.
#
# NOTE on the single-segment URL: the theme's breadcrumb (topbar.html) links every
# intermediate URL segment of a `category` page to `/<segment>/` (root-relative). A
# two-level path like /categories/challenges/hackthebox/ would therefore emit a broken
# link to /challenges/. Keeping the page one level under /categories/ avoids that
# entirely without overriding any theme include.
#
# The global per-name pages (/categories/<name>/) are still produced by jekyll-archives
# and remain used by each post's own category breadcrumb links.
module ScopedCategories
  class Generator < Jekyll::Generator
    safe true
    priority :low

    def generate(site)
      pairs = {} # [parent, child] => [posts]

      site.posts.docs.each do |post|
        cats = Array(post.data['categories'])
        next if cats.size < 2

        parent = cats[0].to_s
        child  = cats[1].to_s
        next if parent.empty? || child.empty?

        (pairs[[parent, child]] ||= []) << post
      end

      seen = {} # slug => [parent, child], guards against slug collisions

      pairs.each do |(parent, child), posts|
        parent_slug = Jekyll::Utils.slugify(parent)
        child_slug  = Jekyll::Utils.slugify(child)

        # Skip degenerate slugs (e.g. a category made only of punctuation) that would
        # otherwise produce a malformed path.
        next if parent_slug.nil? || parent_slug.empty?
        next if child_slug.nil? || child_slug.empty?

        slug = "#{parent_slug}-#{child_slug}"
        if seen.key?(slug)
          Jekyll.logger.warn(
            'ScopedCategories:',
            "slug collision at categories/#{slug} between #{seen[slug].inspect} " \
            "and #{[parent, child].inspect}; skipping the latter."
          )
          next
        end
        seen[slug] = [parent, child]

        posts = posts.sort_by(&:date).reverse
        site.pages << ScopedCategoryPage.new(site, parent, child, slug, posts)
      end
    end
  end

  class ScopedCategoryPage < Jekyll::PageWithoutAFile
    def initialize(site, parent, child, slug, posts)
      super(site, site.source, File.join('categories', slug), 'index.html')

      # NOTE: `parent`/`child` come from the site owner's own post front matter (trusted).
      # The Chirpy `category` layout renders {{ page.title }} unescaped, exactly like the
      # theme does for every other category label, so behaviour is consistent with the theme.
      data['layout'] = 'category'
      data['title']  = "#{parent} › #{child}" # parent › child
      data['posts']  = posts
    end
  end
end
