# frozen_string_literal: true

# Generates SCOPED category pages for each parent -> child pair, i.e. posts whose
# categories[0] == parent AND categories[1] == child.
#
# URL: /categories/<parent-slug>/<child-slug>/
# These back the sub-category links on the Categories (Topics) page so that, e.g.,
# "CTF Competitions -> Challenges" lists only the CTF challenge posts instead of the
# global /categories/challenges/ page.
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

      seen = {} # dest path => [parent, child], guards against slug collisions

      pairs.each do |(parent, child), posts|
        parent_slug = Jekyll::Utils.slugify(parent)
        child_slug  = Jekyll::Utils.slugify(child)

        # Skip degenerate slugs (e.g. a category made only of punctuation) that would
        # otherwise produce a malformed path.
        next if parent_slug.nil? || parent_slug.empty?
        next if child_slug.nil? || child_slug.empty?

        dest = File.join(parent_slug, child_slug)
        if seen.key?(dest)
          Jekyll.logger.warn(
            'ScopedCategories:',
            "slug collision at categories/#{dest} between #{seen[dest].inspect} " \
            "and #{[parent, child].inspect}; skipping the latter."
          )
          next
        end
        seen[dest] = [parent, child]

        posts = posts.sort_by(&:date).reverse
        site.pages << ScopedCategoryPage.new(site, parent, child, parent_slug, child_slug, posts)
      end
    end
  end

  class ScopedCategoryPage < Jekyll::PageWithoutAFile
    def initialize(site, parent, child, parent_slug, child_slug, posts)
      super(site, site.source, File.join('categories', parent_slug, child_slug), 'index.html')

      # NOTE: `parent`/`child` come from the site owner's own post front matter (trusted).
      # The Chirpy `category` layout renders {{ page.title }} unescaped, exactly like the
      # theme does for every other category label, so behaviour is consistent with the theme.
      data['layout'] = 'category'
      data['title']  = "#{parent} › #{child}" # parent › child
      data['posts']  = posts
    end
  end
end
