import type { PostFilter } from "./utils/posts";

export interface SiteConfig {
  title: string;
  slogan: string;
  description?: string;
  site: string,
  social: {
    github?: string;
    linkedin?: string;
    email?: string;
    rss?: boolean;
  };
  homepage: PostFilter;
  googleAnalysis?: string;
  search?: boolean;
}

export const siteConfig: SiteConfig = {
  site: "https://ivancedo.github.io", // your site url
  title: "Your's blog",
  slogan: "Exploring the World with Code",
  description: "write a description here",
  social: {
    github: "https://github.com/ivancedo", // leave empty if you don't want to show the github
    linkedin: "https://www.linkedin.com/in/iv%C3%A1n-ced%C3%B3-marco-b8803b220/", // leave empty if you don't want to show the linkedin
    email: "ivancedo09@gmail.com", // leave empty if you don't want to show the email
    rss: false, // set this to false if you don't want to provide an rss feed
  },
  homepage: {
    maxPosts: 5,
    tags: [],
    excludeTags: [],
  },
  googleAnalysis: "", // your google analysis id
  search: true, // set this to false if you don't want to provide a search feature
};
